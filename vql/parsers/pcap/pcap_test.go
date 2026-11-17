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

package pcap

import (
	"bytes"
	"context"
	"encoding/binary"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/Velocidex/ordereddict"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"www.velocidex.com/golang/velociraptor/acls"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	"www.velocidex.com/golang/vfilter/types"

	_ "www.velocidex.com/golang/velociraptor/accessors/data"
)

type PcapTestSuite struct {
	suite.Suite
}

// nullACLManager allows all permissions in tests.
type nullACLManager struct{}

func (self nullACLManager) CheckAccess(
	permission ...acls.ACL_PERMISSION) (bool, error) {
	return true, nil
}

func (self nullACLManager) CheckAccessWithArgs(
	permission acls.ACL_PERMISSION, args ...string) (bool, error) {
	return true, nil
}

// Build a synthetic ethernet/ipv4/tcp frame.
func tcpFrame(src_ip, dst_ip string, src_port, dst_port uint16,
	payload []byte) []byte {
	return ipFrame(6, src_ip, dst_ip,
		append(tcpHeader(src_port, dst_port, len(payload)), payload...))
}

func udpFrame(src_ip, dst_ip string, src_port, dst_port uint16,
	payload []byte) []byte {
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], src_port)
	binary.BigEndian.PutUint16(udp[2:4], dst_port)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	return ipFrame(17, src_ip, dst_ip, append(udp, payload...))
}

func tcpHeader(src_port, dst_port uint16, payload_len int) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], src_port)
	binary.BigEndian.PutUint16(tcp[2:4], dst_port)
	tcp[12] = 5 << 4 // data offset = 20 bytes
	return tcp
}

func ipFrame(proto uint8, src_ip, dst_ip string, transport []byte) []byte {
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(transport)))
	ip[8] = 64
	ip[9] = proto
	copy(ip[12:16], []byte{10, 0, 0, 1})
	copy(ip[16:20], []byte{10, 0, 0, 2})
	if src_ip == "v6" {
		return v6Frame(proto, transport)
	}
	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)
	return append(eth, append(ip, transport...)...)
}

func v6Frame(proto uint8, transport []byte) []byte {
	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(transport)))
	ip[6] = proto
	ip[7] = 64
	ip[8] = 0x20 // 2001:db8::1
	ip[9] = 0x01
	ip[10] = 0x0d
	ip[11] = 0xb8
	ip[23] = 0x01
	ip[24] = 0x20 // 2001:db8::2
	ip[25] = 0x01
	ip[26] = 0x0d
	ip[27] = 0xb8
	ip[39] = 0x02
	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:14], 0x86dd)
	return append(eth, append(ip, transport...)...)
}

// pcap builders

func pcapFile(order binary.ByteOrder, magic []byte, linktype uint32,
	frames ...[]byte) []byte {
	buf := &bytes.Buffer{}
	buf.Write(magic)
	header := make([]byte, 20)
	order.PutUint16(header[0:2], 2)
	order.PutUint16(header[2:4], 4)
	order.PutUint32(header[12:16], 65535)
	order.PutUint32(header[16:20], linktype)
	buf.Write(header)
	for i, frame := range frames {
		rec := make([]byte, 16)
		order.PutUint32(rec[0:4], uint32(1700000000+i))
		order.PutUint32(rec[4:8], uint32(123456+i))
		order.PutUint32(rec[8:12], uint32(len(frame)))
		order.PutUint32(rec[12:16], uint32(len(frame)))
		buf.Write(rec)
		buf.Write(frame)
	}
	return buf.Bytes()
}

var (
	pcapMagicLE   = []byte{0xd4, 0xc3, 0xb2, 0xa1}
	pcapMagicBE   = []byte{0xa1, 0xb2, 0xc3, 0xd4}
	pcapMagicLENs = []byte{0x4d, 0x3c, 0xb2, 0xa1}
)

// pcapng builders

type pcapngBuilder struct {
	buf   *bytes.Buffer
	order binary.ByteOrder
}

func newPcapng() *pcapngBuilder {
	return &pcapngBuilder{buf: &bytes.Buffer{}}
}

func (self *pcapngBuilder) shb(order binary.ByteOrder) *pcapngBuilder {
	self.order = order
	body := &bytes.Buffer{}
	if order == binary.LittleEndian {
		body.Write([]byte{0x4d, 0x3c, 0x2b, 0x1a})
	} else {
		body.Write([]byte{0x1a, 0x2b, 0x3c, 0x4d})
	}
	fixed := make([]byte, 12)
	order.PutUint16(fixed[0:2], 1) // major
	body.Write(fixed)
	self.writeBlock(blockTypeSHB, body.Bytes())
	return self
}

func (self *pcapngBuilder) idb(linktype uint16, tsresol int) *pcapngBuilder {
	body := make([]byte, 8)
	self.order.PutUint16(body[0:2], linktype)
	self.order.PutUint32(body[4:8], 65535)
	if tsresol >= 0 {
		// if_tsresol option, padded to 32 bits + end_of_options.
		opts := make([]byte, 8+4)
		self.order.PutUint16(opts[0:2], 9)
		self.order.PutUint16(opts[2:4], 1)
		opts[4] = byte(tsresol)
		body = append(body, opts...)
	}
	self.writeBlock(blockTypeIDB, body)
	return self
}

func (self *pcapngBuilder) epb(iface uint32, ts uint64, frame []byte) *pcapngBuilder {
	body := make([]byte, 20)
	self.order.PutUint32(body[0:4], iface)
	self.order.PutUint32(body[4:8], uint32(ts>>32))
	self.order.PutUint32(body[8:12], uint32(ts&0xffffffff))
	self.order.PutUint32(body[12:16], uint32(len(frame)))
	self.order.PutUint32(body[16:20], uint32(len(frame)))
	body = append(body, frame...)
	// Pad packet data to 32 bits.
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	self.writeBlock(blockTypeEPB, body)
	return self
}

func (self *pcapngBuilder) spb(frame []byte) *pcapngBuilder {
	body := make([]byte, 4)
	self.order.PutUint32(body[0:4], uint32(len(frame)))
	body = append(body, frame...)
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	self.writeBlock(blockTypeSPB, body)
	return self
}

func (self *pcapngBuilder) writeBlock(block_type uint32, body []byte) {
	total := uint32(12 + len(body))
	header := make([]byte, 8)
	self.order.PutUint32(header[0:4], block_type)
	if block_type == blockTypeSHB {
		// SHB type is endian neutral.
		binary.BigEndian.PutUint32(header[0:4], blockTypeSHB)
	}
	self.order.PutUint32(header[4:8], total)
	self.buf.Write(header)
	self.buf.Write(body)
	trailer := make([]byte, 4)
	self.order.PutUint32(trailer, total)
	self.buf.Write(trailer)
}

func (self *pcapngBuilder) bytes() []byte {
	return self.buf.Bytes()
}

// Test helpers

func (self *PcapTestSuite) runPlugin(data []byte,
	extra_args ...*ordereddict.Dict) []types.Row {
	args := ordereddict.NewDict().
		Set("filename", string(data)).
		Set("accessor", "data")
	for _, extra := range extra_args {
		for _, k := range extra.Keys() {
			v, _ := extra.Get(k)
			args.Set(k, v)
		}
	}

	log_buffer := &strings.Builder{}
	scope := vql_subsystem.MakeScope()
	scope.SetLogger(log.New(log_buffer, "", 0))
	scope.AppendVars(ordereddict.NewDict().
		Set(vql_subsystem.ACL_MANAGER_VAR, nullACLManager{}))
	defer scope.Close()

	plugin := ParsePcapPlugin{}
	rows := []types.Row{}
	for row := range plugin.Call(context.Background(), scope, args) {
		rows = append(rows, row)
	}
	self.Empty(log_buffer.String(), "unexpected log output")
	return rows
}

func getString(row types.Row, key string) string {
	d, ok := row.(*ordereddict.Dict)
	if !ok {
		return ""
	}
	v, pres := d.Get(key)
	if !pres || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case time.Time:
		return t.String()
	}
	return ""
}

func (self *PcapTestSuite) TestPcapLittleEndian() {
	frame1 := tcpFrame("", "", 1234, 80, []byte("GET / HTTP/1.0\r\n\r\n"))
	frame2 := udpFrame("", "", 53, 5353, []byte("dns-query"))
	data := pcapFile(binary.LittleEndian, pcapMagicLE, 1, frame1, frame2)

	rows := self.runPlugin(data)
	assert.Equal(self.T(), 2, len(rows))

	assert.Equal(self.T(), "ethernet", getString(rows[0], "LinkType"))
	assert.Equal(self.T(), "10.0.0.1", getString(rows[0], "SrcIP"))
	assert.Equal(self.T(), "10.0.0.2", getString(rows[0], "DstIP"))
	assert.Equal(self.T(), "TCP", getString(rows[0], "Protocol"))
	assert.Equal(self.T(), "474554202f20485454502f312e300d0a0d0a",
		getString(rows[0], "Payload"))

	assert.Equal(self.T(), "UDP", getString(rows[1], "Protocol"))
	assert.Equal(self.T(), "646e732d7175657279",
		getString(rows[1], "Payload"))
}

func (self *PcapTestSuite) TestPcapBigEndianAndIPv6() {
	frame := tcpFrame("v6", "", 443, 9000, []byte("hi"))
	data := pcapFile(binary.BigEndian, pcapMagicBE, 1, frame)

	rows := self.runPlugin(data)
	assert.Equal(self.T(), 1, len(rows))
	assert.Equal(self.T(), "2001:db8::1", getString(rows[0], "SrcIP"))
	assert.Equal(self.T(), "2001:db8::2", getString(rows[0], "DstIP"))
	assert.Equal(self.T(), "TCP", getString(rows[0], "Protocol"))
}

func (self *PcapTestSuite) TestPcapNanosecondMagic() {
	frame := udpFrame("", "", 1, 2, []byte("x"))
	data := pcapFile(binary.LittleEndian, pcapMagicLENs, 1, frame)
	rows := self.runPlugin(data)
	assert.Equal(self.T(), 1, len(rows))
	assert.Equal(self.T(), "UDP", getString(rows[0], "Protocol"))
}

func (self *PcapTestSuite) TestProtocolFilter() {
	frames := [][]byte{
		tcpFrame("", "", 1234, 80, []byte("a")),
		udpFrame("", "", 53, 5353, []byte("b")),
		tcpFrame("", "", 1234, 443, []byte("c")),
	}
	data := pcapFile(binary.LittleEndian, pcapMagicLE, 1, frames...)

	rows := self.runPlugin(data,
		ordereddict.NewDict().Set("protocol", "udp"))
	assert.Equal(self.T(), 1, len(rows))
	assert.Equal(self.T(), "UDP", getString(rows[0], "Protocol"))
}

func (self *PcapTestSuite) TestPortFilter() {
	frames := [][]byte{
		tcpFrame("", "", 1234, 80, []byte("a")),
		tcpFrame("", "", 1234, 443, []byte("c")),
	}
	data := pcapFile(binary.LittleEndian, pcapMagicLE, 1, frames...)

	rows := self.runPlugin(data,
		ordereddict.NewDict().Set("port", int64(443)))
	assert.Equal(self.T(), 1, len(rows))
}

func (self *PcapTestSuite) TestLimit() {
	frames := [][]byte{
		tcpFrame("", "", 1, 80, []byte("a")),
		tcpFrame("", "", 2, 80, []byte("b")),
		tcpFrame("", "", 3, 80, []byte("c")),
	}
	data := pcapFile(binary.LittleEndian, pcapMagicLE, 1, frames...)

	rows := self.runPlugin(data,
		ordereddict.NewDict().Set("limit", int64(2)))
	assert.Equal(self.T(), 2, len(rows))
}

func (self *PcapTestSuite) TestPayloadTruncation() {
	frame := tcpFrame("", "", 1, 80, []byte("0123456789abcdef"))
	data := pcapFile(binary.LittleEndian, pcapMagicLE, 1, frame)

	rows := self.runPlugin(data,
		ordereddict.NewDict().Set("payload_bytes", int64(4)))
	assert.Equal(self.T(), 1, len(rows))
	// 4 bytes -> 8 hex chars.
	assert.Equal(self.T(), "30313233", getString(rows[0], "Payload"))
}

func (self *PcapTestSuite) TestTruncatedPacket() {
	good := tcpFrame("", "", 1, 80, []byte("ok"))
	data := pcapFile(binary.LittleEndian, pcapMagicLE, 1, good)
	// Append a record header claiming more data than remains.
	rec := make([]byte, 16)
	binary.LittleEndian.PutUint32(rec[8:12], 1000)
	binary.LittleEndian.PutUint32(rec[12:16], 1000)
	data = append(data, rec...)
	data = append(data, []byte("short")...)

	rows := self.runPlugin(data)
	assert.Equal(self.T(), 2, len(rows))
	assert.Equal(self.T(), "", getString(rows[0], "ErrorType"))
	assert.Equal(self.T(), ErrTypeTruncatedPacket,
		getString(rows[1], "ErrorType"))
}

func (self *PcapTestSuite) TestUnknownLinkType() {
	frame := []byte{0xde, 0xad, 0xbe, 0xef}
	data := pcapFile(binary.LittleEndian, pcapMagicLE, 999, frame, frame)

	rows := self.runPlugin(data)
	assert.Equal(self.T(), 2, len(rows))
	// First packet reports the unknown link type.
	assert.Equal(self.T(), ErrTypeUnknownLinkType,
		getString(rows[0], "ErrorType"))
	// The raw frame is still available as payload.
	assert.Equal(self.T(), "deadbeef", getString(rows[0], "Payload"))
	// Reported only once - second packet has no error.
	assert.Equal(self.T(), "", getString(rows[1], "ErrorType"))
	assert.Equal(self.T(), "deadbeef", getString(rows[1], "Payload"))
}

func (self *PcapTestSuite) TestCorruptPcapHeader() {
	rows := self.runPlugin([]byte("this is not a pcap file at all..."))
	assert.Equal(self.T(), 1, len(rows))
	assert.Equal(self.T(), ErrTypeCorruptHeader,
		getString(rows[0], "ErrorType"))
}

func (self *PcapTestSuite) TestPcapngBasic() {
	frame := tcpFrame("", "", 8080, 3128, []byte("payload"))
	ng := newPcapng().
		shb(binary.LittleEndian).
		idb(1, -1).
		epb(0, 1700000000_000000, frame)

	rows := self.runPlugin(ng.bytes())
	assert.Equal(self.T(), 1, len(rows))
	assert.Equal(self.T(), "TCP", getString(rows[0], "Protocol"))
	assert.Equal(self.T(), "ethernet", getString(rows[0], "LinkType"))
	assert.Equal(self.T(), "2023-11-14 22:13:20 +0000 UTC",
		getString(rows[0], "Timestamp"))
}

func (self *PcapTestSuite) TestPcapngMultipleSectionsMixedEndian() {
	frame_le := tcpFrame("", "", 1, 80, []byte("le"))
	frame_be := udpFrame("", "", 2, 53, []byte("be"))

	ng := newPcapng().
		shb(binary.LittleEndian).
		idb(1, -1).
		epb(0, 1700000000_000000, frame_le).
		// Second section switches to big endian.
		shb(binary.BigEndian).
		idb(1, -1).
		epb(0, 1700000001_000000, frame_be)

	rows := self.runPlugin(ng.bytes())
	assert.Equal(self.T(), 2, len(rows))
	assert.Equal(self.T(), "TCP", getString(rows[0], "Protocol"))
	assert.Equal(self.T(), "UDP", getString(rows[1], "Protocol"))
}

func (self *PcapTestSuite) TestPcapngTsresol() {
	frame := tcpFrame("", "", 1, 80, []byte("x"))
	// Millisecond resolution: ts=1700000000123 ms.
	ng := newPcapng().
		shb(binary.LittleEndian).
		idb(1, 3).
		epb(0, 1700000000123, frame)

	rows := self.runPlugin(ng.bytes())
	assert.Equal(self.T(), 1, len(rows))
	assert.Equal(self.T(), "2023-11-14 22:13:20.123 +0000 UTC",
		getString(rows[0], "Timestamp"))
}

func (self *PcapTestSuite) TestPcapngSimplePacketBlock() {
	frame := udpFrame("", "", 9, 9, []byte("spb"))
	ng := newPcapng().
		shb(binary.LittleEndian).
		idb(1, -1).
		spb(frame)

	rows := self.runPlugin(ng.bytes())
	assert.Equal(self.T(), 1, len(rows))
	assert.Equal(self.T(), "UDP", getString(rows[0], "Protocol"))
}

func (self *PcapTestSuite) TestPcapngCorruptBlockRecovery() {
	good1 := tcpFrame("", "", 1, 80, []byte("good1"))
	good2 := tcpFrame("", "", 2, 80, []byte("good2"))

	ng := newPcapng().
		shb(binary.LittleEndian).
		idb(1, -1).
		epb(0, 1700000000_000000, good1).
		epb(0, 1700000000_500000, good1)
	data := ng.bytes()

	// Corrupt the trailing block length of the second EPB - its
	// packet is lost but parsing must continue.
	data[len(data)-4] ^= 0xff

	// A valid second section follows the corrupt block.
	ng2 := newPcapng().
		shb(binary.LittleEndian).
		idb(1, -1).
		epb(0, 1700000001_000000, good2)
	data = append(data, ng2.bytes()...)

	rows := self.runPlugin(data)
	assert.Equal(self.T(), 3, len(rows))
	assert.Equal(self.T(), "", getString(rows[0], "ErrorType"))
	assert.Equal(self.T(), ErrTypeCorruptBlock,
		getString(rows[1], "ErrorType"))
	// Parsing recovers into the next section.
	assert.Equal(self.T(), "", getString(rows[2], "ErrorType"))
	assert.Equal(self.T(), "TCP", getString(rows[2], "Protocol"))
}

func (self *PcapTestSuite) TestPcapngCorruptSectionHeaderRecovery() {
	good := udpFrame("", "", 5, 5, []byte("next"))

	// A section with a garbage byte order magic.
	bad := &bytes.Buffer{}
	bad.Write([]byte{0x0A, 0x0D, 0x0D, 0x0A})
	bad.Write([]byte{0xde, 0xad, 0xbe, 0xef}) // invalid BOM
	bad.Write(bytes.Repeat([]byte{0x41}, 20))

	ng := newPcapng().
		shb(binary.LittleEndian).
		idb(1, -1).
		epb(0, 1700000000_000000, good)
	data := append(bad.Bytes(), ng.bytes()...)

	rows := self.runPlugin(data)
	assert.Equal(self.T(), 2, len(rows))
	assert.Equal(self.T(), ErrTypeCorruptHeader,
		getString(rows[0], "ErrorType"))
	assert.Equal(self.T(), "UDP", getString(rows[1], "Protocol"))
}

func (self *PcapTestSuite) TestPcapngTruncatedPacket() {
	frame := tcpFrame("", "", 1, 80, []byte("x"))
	ng := newPcapng().
		shb(binary.LittleEndian).
		idb(1, -1)
	ng.epb(0, 1700000000_000000, frame)
	data := ng.bytes()
	// Chop the file mid-packet.
	data = data[:len(data)-10]

	rows := self.runPlugin(data)
	assert.Equal(self.T(), 1, len(rows))
	assert.Equal(self.T(), ErrTypeTruncatedPacket,
		getString(rows[0], "ErrorType"))
}

func (self *PcapTestSuite) TestPcapngUnknownInterface() {
	frame := tcpFrame("", "", 1, 80, []byte("x"))
	ng := newPcapng().
		shb(binary.LittleEndian).
		idb(1, -1).
		epb(7, 1700000000_000000, frame) // no interface 7

	rows := self.runPlugin(ng.bytes())
	assert.Equal(self.T(), 1, len(rows))
	assert.Equal(self.T(), ErrTypeCorruptBlock,
		getString(rows[0], "ErrorType"))
}

func TestPcapPlugin(t *testing.T) {
	suite.Run(t, &PcapTestSuite{})
}
