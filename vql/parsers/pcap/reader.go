/*
Velociraptor - Dig Deeper
Copyright (C) 2019-2025 Rapid7 Inc.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

// Package pcap implements a streaming parser for pcap and pcapng
// capture files. The parser reads packets one at a time from an
// io.Reader with a bounded memory footprint - the whole capture is
// never loaded into memory.
package pcap

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// Distinguishable error categories surfaced on Packet.ErrorType.
const (
	ErrTypeCorruptHeader   = "corrupt_header"
	ErrTypeCorruptBlock    = "corrupt_block"
	ErrTypeTruncatedPacket = "truncated_packet"
	ErrTypeUnknownLinkType = "unknown_linktype"
)

const (
	// Hard caps to keep memory bounded regardless of what the file
	// claims. A captured packet larger than this is treated as
	// corruption.
	maxPacketSize = 16 * 1024 * 1024
	maxBlockSize  = 64 * 1024 * 1024
)

// Block types used by pcapng.
const (
	blockTypeSHB = 0x0A0D0D0A
	blockTypeIDB = 0x00000001
	blockTypeSPB = 0x00000003
	blockTypeEPB = 0x00000006
)

// Packet is a single parsed record. When Error is set the packet
// carries a recoverable, distinguishable parsing error and the
// reader may continue with subsequent packets.
type Packet struct {
	Timestamp time.Time
	LinkType  uint32

	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol string

	// Length is the original on-wire length, CapLength the captured
	// length.
	Length    uint32
	CapLength uint32

	// Payload is the (possibly truncated) transport layer payload.
	Payload []byte

	// Error/ErrorType are set for recoverable errors.
	Error     string
	ErrorType string
}

// Reader streams packets from a pcap or pcapng capture.
type Reader struct {
	r *bufio.Reader

	// Parser state - exactly one of these is active depending on
	// the file format detected from the first bytes.
	pcap   *pcapState
	pcapng *pcapngState
}

type pcapState struct {
	order    binary.ByteOrder
	nanos    bool
	linktype uint32
	snaplen  uint32
	started  bool

	dec *decodeState
}

type pcapngInterface struct {
	linktype uint32
	// tsresol is the timestamp resolution as a negative power: if
	// base2 is set the timestamp unit is 2^-tsresol seconds,
	// otherwise 10^-tsresol seconds.
	tsresol uint8
	base2   bool
}

type pcapngState struct {
	order   binary.ByteOrder
	ifaces  []pcapngInterface
	started bool

	// pendingSHB holds the 8 byte preamble of a section header
	// block discovered by resync() - it is processed by the next
	// call to nextPcapngBlock.
	pendingSHB []byte

	dec *decodeState
}

// NewReader detects the capture format (pcap or pcapng) from the
// stream and returns a streaming packet reader.
func NewReader(r io.Reader) (*Reader, error) {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReaderSize(r, 64*1024)
	}

	res := &Reader{r: br}

	magic, err := br.Peek(4)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to read file magic: %w",
			ErrTypeCorruptHeader, err)
	}

	switch {
	// pcapng section header block - endian neutral magic.
	case magic[0] == 0x0A && magic[1] == 0x0D &&
		magic[2] == 0x0D && magic[3] == 0x0A:
		res.pcapng = &pcapngState{
			order: binary.LittleEndian,
			dec:   newDecodeState(),
		}

	// pcap magic numbers (microsecond and nanosecond resolution,
	// both endiannesses).
	case magic[0] == 0xd4 && magic[1] == 0xc3 &&
		magic[2] == 0xb2 && magic[3] == 0xa1:
		res.pcap = &pcapState{order: binary.LittleEndian, dec: newDecodeState()}
	case magic[0] == 0xa1 && magic[1] == 0xb2 &&
		magic[2] == 0xc3 && magic[3] == 0xd4:
		res.pcap = &pcapState{order: binary.BigEndian, dec: newDecodeState()}
	case magic[0] == 0x4d && magic[1] == 0x3c &&
		magic[2] == 0xb2 && magic[3] == 0xa1:
		res.pcap = &pcapState{order: binary.LittleEndian, nanos: true, dec: newDecodeState()}
	case magic[0] == 0xa1 && magic[1] == 0xb2 &&
		magic[2] == 0x3c && magic[3] == 0x4d:
		res.pcap = &pcapState{order: binary.BigEndian, nanos: true, dec: newDecodeState()}

	default:
		return nil, fmt.Errorf(
			"%s: unrecognized file magic % x - not a pcap or pcapng file",
			ErrTypeCorruptHeader, magic)
	}
	return res, nil
}

// Next returns the next packet in the capture, or io.EOF when the
// capture is exhausted. Recoverable corruption is reported on the
// returned Packet's Error/ErrorType fields with a nil error - the
// caller may keep calling Next() to continue with later packets.
func (self *Reader) Next() (*Packet, error) {
	if self.pcap != nil {
		return self.nextPcap()
	}
	return self.nextPcapng()
}

// ---------------- classic pcap ----------------

func (self *Reader) readPcapGlobalHeader() error {
	state := self.pcap
	// Magic already peeked - consume the remaining 20 header bytes.
	header := make([]byte, 24)
	if _, err := io.ReadFull(self.r, header); err != nil {
		return fmt.Errorf("%s: truncated pcap global header: %w",
			ErrTypeCorruptHeader, err)
	}
	state.snaplen = state.order.Uint32(header[16:20])
	state.linktype = state.order.Uint32(header[20:24])
	if state.snaplen == 0 || state.snaplen > maxPacketSize {
		state.snaplen = maxPacketSize
	}
	state.started = true
	return nil
}

func (self *Reader) nextPcap() (*Packet, error) {
	state := self.pcap
	if !state.started {
		if err := self.readPcapGlobalHeader(); err != nil {
			return nil, err
		}
	}

	header := make([]byte, 16)
	_, err := io.ReadFull(self.r, header)
	if err == io.EOF {
		return nil, io.EOF
	}
	if err == io.ErrUnexpectedEOF {
		return &Packet{
			Error:     "truncated packet header at end of file",
			ErrorType: ErrTypeTruncatedPacket,
		}, nil
	}
	if err != nil {
		return nil, err
	}

	ts_sec := state.order.Uint32(header[0:4])
	ts_frac := state.order.Uint32(header[4:8])
	incl_len := state.order.Uint32(header[8:12])
	orig_len := state.order.Uint32(header[12:16])

	if incl_len > maxPacketSize {
		// A record this large means the stream is desynchronized
		// or corrupt. Classic pcap has no framing to resynchronize
		// with, so this terminates the file.
		return &Packet{
			CapLength: incl_len,
			Length:    orig_len,
			Error: fmt.Sprintf(
				"implausible captured length %d - corrupt packet header",
				incl_len),
			ErrorType: ErrTypeCorruptHeader,
		}, nil
	}

	data := make([]byte, incl_len)
	n, err := io.ReadFull(self.r, data)
	if err != nil {
		return &Packet{
			CapLength: incl_len,
			Length:    orig_len,
			Error: fmt.Sprintf(
				"truncated packet: expected %d bytes, got %d",
				incl_len, n),
			ErrorType: ErrTypeTruncatedPacket,
		}, nil
	}

	ts := int64(ts_sec)*1e9 + int64(ts_frac)*1e3
	if state.nanos {
		ts = int64(ts_sec)*1e9 + int64(ts_frac)
	}

	pkt := &Packet{
		Timestamp: time.Unix(0, ts).UTC(),
		LinkType:  state.linktype,
		Length:    orig_len,
		CapLength: incl_len,
	}
	decodePacket(pkt, data, state.dec)
	return pkt, nil
}

// ---------------- pcapng ----------------

// resync scans forward for the next section header block magic,
// allowing parsing to continue after a corrupt block. On success
// the section's 8 byte preamble is stashed in pendingSHB and
// processed by the next call. Returns io.EOF if no further
// section is found.
func (self *Reader) resync() error {
	var window [4]byte
	for {
		b, err := self.r.ReadByte()
		if err != nil {
			return io.EOF
		}
		window[0], window[1], window[2] = window[1], window[2], window[3]
		window[3] = b
		if window[0] == 0x0A && window[1] == 0x0D &&
			window[2] == 0x0D && window[3] == 0x0A {
			rest := make([]byte, 4)
			if _, err := io.ReadFull(self.r, rest); err != nil {
				return io.EOF
			}
			header := make([]byte, 8)
			copy(header[0:4], window[:])
			copy(header[4:8], rest)
			self.pcapng.pendingSHB = header
			return nil
		}
	}
}

func (self *Reader) nextPcapng() (*Packet, error) {
	for {
		pkt, err := self.nextPcapngBlock()
		if err != nil {
			return nil, err
		}
		if pkt != nil {
			return pkt, nil
		}
		// nil packet: block consumed, keep going.
	}
}

// nextPcapngBlock processes a single block. It returns a nil packet
// for blocks that carry no packet data (interfaces, metadata).
func (self *Reader) nextPcapngBlock() (*Packet, error) {
	state := self.pcapng

	// A resync after corruption may have already located the next
	// section header.
	if state.pendingSHB != nil {
		header := state.pendingSHB
		state.pendingSHB = nil
		return self.readSHB(header)
	}

	header := make([]byte, 8)
	_, err := io.ReadFull(self.r, header)
	if err == io.EOF {
		return nil, io.EOF
	}
	if err == io.ErrUnexpectedEOF {
		return nil, fmt.Errorf("%s: truncated pcapng block header: %w",
			ErrTypeCorruptHeader, err)
	}
	if err != nil {
		return nil, err
	}

	is_shb := header[0] == 0x0A && header[1] == 0x0D &&
		header[2] == 0x0D && header[3] == 0x0A

	if is_shb {
		return self.readSHB(header)
	}

	if !state.started {
		// File did not begin with a section header - attempt to
		// resynchronize with the next section.
		if err := self.resync(); err != nil {
			return nil, fmt.Errorf(
				"%s: missing section header and no further section found",
				ErrTypeCorruptHeader)
		}
		return &Packet{
			Error: "corrupt file: expected section header block, " +
				"resynchronized to next section",
			ErrorType: ErrTypeCorruptHeader,
		}, nil
	}

	block_type := state.order.Uint32(header[0:4])
	total_len := state.order.Uint32(header[4:8])

	if total_len < 12 || total_len > maxBlockSize {
		// Desynchronized stream - scan for the next section.
		if err := self.resync(); err != nil {
			return nil, io.EOF
		}
		return &Packet{
			Error: fmt.Sprintf(
				"corrupt block: implausible block length %d, "+
					"resynchronized to next section", total_len),
			ErrorType: ErrTypeCorruptBlock,
		}, nil
	}

	body := make([]byte, total_len-8)
	if _, err := io.ReadFull(self.r, body); err != nil {
		return &Packet{
			Error: fmt.Sprintf(
				"truncated block (type %d): expected %d bytes: %v",
				block_type, total_len, err),
			ErrorType: ErrTypeTruncatedPacket,
		}, nil
	}

	// Verify the trailing total length matches.
	trailing := state.order.Uint32(body[len(body)-4:])
	if trailing != total_len {
		// The block framing is broken but the block boundary is
		// known, so continue with the next block.
		return &Packet{
			Error: fmt.Sprintf(
				"corrupt block (type %d): trailing length %d does "+
					"not match block length %d",
				block_type, trailing, total_len),
			ErrorType: ErrTypeCorruptBlock,
		}, nil
	}
	body = body[:len(body)-4]

	switch block_type {
	case blockTypeIDB:
		return self.readIDB(body)
	case blockTypeEPB:
		return self.readEPB(body)
	case blockTypeSPB:
		return self.readSPB(body)
	default:
		// Unknown/uninteresting block (name resolution, secrets,
		// statistics etc) - skip it.
		return nil, nil
	}
}

// readSHB parses a section header block. Multiple sections may
// appear in one file, each with its own byte order. The 8 byte
// block preamble has already been consumed and is passed in -
// the total length field it carries can only be interpreted once
// the section's byte order is known.
func (self *Reader) readSHB(header []byte) (*Packet, error) {
	state := self.pcapng

	// Read the byte order magic first to determine this section's
	// endianness.
	bom := make([]byte, 4)
	if _, err := io.ReadFull(self.r, bom); err != nil {
		return nil, fmt.Errorf("%s: truncated section header: %w",
			ErrTypeCorruptHeader, err)
	}

	switch {
	case bom[0] == 0x4d && bom[1] == 0x3c && bom[2] == 0x2b && bom[3] == 0x1a:
		state.order = binary.LittleEndian
	case bom[0] == 0x1a && bom[1] == 0x2b && bom[2] == 0x3c && bom[3] == 0x4d:
		state.order = binary.BigEndian
	default:
		// Corrupt section header - resync to the next section.
		if err := self.resync(); err != nil {
			return nil, io.EOF
		}
		return &Packet{
			Error: fmt.Sprintf(
				"corrupt section header: invalid byte order magic % x, "+
					"resynchronized to next section", bom),
			ErrorType: ErrTypeCorruptHeader,
		}, nil
	}

	// Now read the rest of the fixed section header: major (2),
	// minor (2), section length (8). The block total length was
	// already consumed as part of the block preamble and is
	// reinterpreted with this section's byte order.
	fixed := make([]byte, 12)
	if _, err := io.ReadFull(self.r, fixed); err != nil {
		return nil, fmt.Errorf("%s: truncated section header: %w",
			ErrTypeCorruptHeader, err)
	}
	total_len := state.order.Uint32(header[4:8])
	if total_len < 28 || total_len > maxBlockSize {
		if err := self.resync(); err != nil {
			return nil, io.EOF
		}
		return &Packet{
			Error: fmt.Sprintf(
				"corrupt section header: implausible block length %d, "+
					"resynchronized to next section", total_len),
			ErrorType: ErrTypeCorruptHeader,
		}, nil
	}

	// Skip options and the trailing block length: 8 bytes of block
	// preamble, 4 of byte order magic and 12 of fixed header have
	// been consumed already.
	if _, err := io.CopyN(io.Discard, self.r, int64(total_len)-24); err != nil {
		return nil, fmt.Errorf("%s: truncated section header: %w",
			ErrTypeCorruptHeader, err)
	}

	// A new section resets the interface list.
	state.ifaces = nil
	state.started = true
	return nil, nil
}

// parseOptions extracts if_tsresol from an interface description
// block's options area.
func parseOptions(state *pcapngState, opts []byte, iface *pcapngInterface) {
	for len(opts) >= 4 {
		code := state.order.Uint16(opts[0:2])
		length := int(state.order.Uint16(opts[2:4]))
		opts = opts[4:]
		if code == 0 {
			return
		}
		if length > len(opts) {
			return
		}
		if code == 9 && length >= 1 { // if_tsresol
			value := opts[0]
			if value&0x80 != 0 {
				iface.base2 = true
				iface.tsresol = value & 0x7f
			} else {
				iface.tsresol = value
			}
		}
		// Options are padded to 32 bits.
		padded := (length + 3) &^ 3
		if padded > len(opts) {
			return
		}
		opts = opts[padded:]
	}
}

func (self *Reader) readIDB(body []byte) (*Packet, error) {
	state := self.pcapng
	if len(body) < 8 {
		return &Packet{
			Error:     "corrupt interface description block: too short",
			ErrorType: ErrTypeCorruptBlock,
		}, nil
	}
	iface := pcapngInterface{
		linktype: uint32(state.order.Uint16(body[0:2])),
		tsresol:  6, // Default resolution is microseconds.
	}
	parseOptions(state, body[8:], &iface)
	state.ifaces = append(state.ifaces, iface)
	return nil, nil
}

func (self *Reader) timestamp(iface pcapngInterface, ts uint64) time.Time {
	var nanos int64
	if iface.base2 {
		// 2^-n second resolution.
		sec := ts >> iface.tsresol
		frac := ts & ((1 << iface.tsresol) - 1)
		nanos = int64(sec)*1e9 +
			int64(frac)*1e9/int64(1<<iface.tsresol)
	} else {
		// 10^-n second resolution - scale to nanoseconds.
		scale := uint64(1)
		resol := int(iface.tsresol)
		for i := 0; i < resol && i < 9; i++ {
			scale *= 10
		}
		sec := ts / scale
		frac := ts % scale
		mult := uint64(1)
		for i := resol; i < 9; i++ {
			mult *= 10
		}
		nanos = int64(sec)*1e9 + int64(frac*mult)
	}
	return time.Unix(0, nanos).UTC()
}

func (self *Reader) readEPB(body []byte) (*Packet, error) {
	state := self.pcapng
	if len(body) < 20 {
		return &Packet{
			Error:     "corrupt enhanced packet block: too short",
			ErrorType: ErrTypeCorruptBlock,
		}, nil
	}
	iface_id := state.order.Uint32(body[0:4])
	ts_high := state.order.Uint32(body[4:8])
	ts_low := state.order.Uint32(body[8:12])
	caplen := state.order.Uint32(body[12:16])
	origlen := state.order.Uint32(body[16:20])

	if iface_id >= uint32(len(state.ifaces)) {
		return &Packet{
			CapLength: caplen,
			Length:    origlen,
			Error: fmt.Sprintf(
				"corrupt enhanced packet block: unknown interface id %d",
				iface_id),
			ErrorType: ErrTypeCorruptBlock,
		}, nil
	}
	iface := state.ifaces[iface_id]

	if caplen > maxPacketSize || int(caplen) > len(body)-20 {
		return &Packet{
			CapLength: caplen,
			Length:    origlen,
			LinkType:  iface.linktype,
			Timestamp: self.timestamp(iface,
				uint64(ts_high)<<32|uint64(ts_low)),
			Error: fmt.Sprintf(
				"truncated packet: captured length %d exceeds block data %d",
				caplen, len(body)-20),
			ErrorType: ErrTypeTruncatedPacket,
		}, nil
	}

	data := body[20 : 20+caplen]
	pkt := &Packet{
		Timestamp: self.timestamp(iface,
			uint64(ts_high)<<32|uint64(ts_low)),
		LinkType:  iface.linktype,
		Length:    origlen,
		CapLength: caplen,
	}
	decodePacket(pkt, data, state.dec)
	return pkt, nil
}

func (self *Reader) readSPB(body []byte) (*Packet, error) {
	state := self.pcapng
	if len(body) < 4 {
		return &Packet{
			Error:     "corrupt simple packet block: too short",
			ErrorType: ErrTypeCorruptBlock,
		}, nil
	}
	origlen := state.order.Uint32(body[0:4])

	var linktype uint32
	if len(state.ifaces) > 0 {
		linktype = state.ifaces[0].linktype
	}

	// The simple packet block carries no timestamp or interface.
	data := body[4:]
	if uint32(len(data)) > origlen {
		data = data[:origlen]
	}
	pkt := &Packet{
		LinkType:  linktype,
		Length:    origlen,
		CapLength: uint32(len(data)),
	}
	decodePacket(pkt, data, state.dec)
	return pkt, nil
}
