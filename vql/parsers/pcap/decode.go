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
	"encoding/binary"
	"fmt"
	"net"
)

// Link types we know how to decode (LINKTYPE_* values).
const (
	linkTypeNull      = 0   // BSD loopback
	linkTypeEthernet  = 1   // Ethernet
	linkTypeRaw       = 101 // Raw IPv4/IPv6
	linkTypeLinuxSLL  = 113 // Linux cooked capture v1
	linkTypeLinuxSLL2 = 276 // Linux cooked capture v2
)

// LinkTypeName returns a human readable name for a link type.
func LinkTypeName(linktype uint32) string {
	switch linktype {
	case linkTypeNull:
		return "null"
	case linkTypeEthernet:
		return "ethernet"
	case linkTypeRaw:
		return "raw"
	case linkTypeLinuxSLL:
		return "linux_sll"
	case linkTypeLinuxSLL2:
		return "linux_sll2"
	default:
		return fmt.Sprintf("unknown(%d)", linktype)
	}
}

// decodeState tracks per-capture decoding state so recurring
// conditions (like an unknown link type) are only reported once.
type decodeState struct {
	unknownLinkTypeReported map[uint32]bool
}

func newDecodeState() *decodeState {
	return &decodeState{unknownLinkTypeReported: map[uint32]bool{}}
}

// decodePacket extracts the 5 tuple and payload from a link layer
// frame, filling in pkt in place. Unknown link types are reported
// once per capture; the raw frame is still exposed as the payload
// so no data is lost.
func decodePacket(pkt *Packet, data []byte, state *decodeState) {
	var ethertype uint16
	var network []byte

	switch pkt.LinkType {
	case linkTypeEthernet:
		if len(data) < 14 {
			pkt.Error = "truncated ethernet header"
			pkt.ErrorType = ErrTypeTruncatedPacket
			pkt.Payload = data
			return
		}
		ethertype = binary.BigEndian.Uint16(data[12:14])
		network = data[14:]
		// Skip VLAN/QinQ tags.
		for ethertype == 0x8100 || ethertype == 0x88a8 || ethertype == 0x9100 {
			if len(network) < 4 {
				pkt.Error = "truncated vlan tag"
				pkt.ErrorType = ErrTypeTruncatedPacket
				pkt.Payload = data
				return
			}
			ethertype = binary.BigEndian.Uint16(network[2:4])
			network = network[4:]
		}

	case linkTypeNull:
		if len(data) < 4 {
			pkt.Error = "truncated loopback header"
			pkt.ErrorType = ErrTypeTruncatedPacket
			pkt.Payload = data
			return
		}
		// The address family is stored in host byte order - accept
		// either interpretation.
		family_le := binary.LittleEndian.Uint32(data[0:4])
		family_be := binary.BigEndian.Uint32(data[0:4])
		switch {
		case family_le == 2 || family_be == 2:
			ethertype = 0x0800
		case family_le == 24 || family_le == 28 || family_le == 30 ||
			family_be == 24 || family_be == 28 || family_be == 30 ||
			family_le == 10 || family_be == 10:
			ethertype = 0x86dd
		default:
			ethertype = 0
		}
		network = data[4:]

	case linkTypeRaw:
		network = data
		if len(data) > 0 && data[0]>>4 == 6 {
			ethertype = 0x86dd
		} else {
			ethertype = 0x0800
		}

	case linkTypeLinuxSLL:
		if len(data) < 16 {
			pkt.Error = "truncated linux sll header"
			pkt.ErrorType = ErrTypeTruncatedPacket
			pkt.Payload = data
			return
		}
		ethertype = binary.BigEndian.Uint16(data[14:16])
		network = data[16:]

	case linkTypeLinuxSLL2:
		if len(data) < 20 {
			pkt.Error = "truncated linux sll2 header"
			pkt.ErrorType = ErrTypeTruncatedPacket
			pkt.Payload = data
			return
		}
		ethertype = binary.BigEndian.Uint16(data[0:2])
		network = data[20:]

	default:
		// Unknown link type - report once per capture but keep
		// emitting packets with the raw frame as payload.
		if !state.unknownLinkTypeReported[pkt.LinkType] {
			state.unknownLinkTypeReported[pkt.LinkType] = true
			pkt.Error = fmt.Sprintf(
				"unknown link type %d - emitting raw frames without decoding",
				pkt.LinkType)
			pkt.ErrorType = ErrTypeUnknownLinkType
		}
		pkt.Payload = data
		return
	}

	switch ethertype {
	case 0x0800:
		decodeIPv4(pkt, network)
	case 0x86dd:
		decodeIPv6(pkt, network)
	default:
		// Non IP traffic (ARP etc) - no 5 tuple, expose the
		// network layer bytes as payload.
		pkt.Protocol = fmt.Sprintf("ethertype_0x%04x", ethertype)
		pkt.Payload = network
	}
}

func decodeIPv4(pkt *Packet, data []byte) {
	if len(data) < 20 {
		pkt.Error = "truncated ipv4 header"
		pkt.ErrorType = ErrTypeTruncatedPacket
		pkt.Payload = data
		return
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || len(data) < ihl {
		pkt.Error = "truncated ipv4 options"
		pkt.ErrorType = ErrTypeTruncatedPacket
		pkt.Payload = data
		return
	}
	pkt.SrcIP = net.IP(data[12:16]).String()
	pkt.DstIP = net.IP(data[16:20]).String()
	decodeTransport(pkt, data[0]>>4, data[9], data[ihl:])
}

func decodeIPv6(pkt *Packet, data []byte) {
	if len(data) < 40 {
		pkt.Error = "truncated ipv6 header"
		pkt.ErrorType = ErrTypeTruncatedPacket
		pkt.Payload = data
		return
	}
	pkt.SrcIP = net.IP(data[8:24]).String()
	pkt.DstIP = net.IP(data[24:40]).String()

	next_header := data[6]
	rest := data[40:]

	// Walk extension headers.
	for {
		switch next_header {
		case 0, 43, 60: // hop-by-hop, routing, destination options
			if len(rest) < 8 {
				pkt.Error = "truncated ipv6 extension header"
				pkt.ErrorType = ErrTypeTruncatedPacket
				pkt.Payload = rest
				return
			}
			hdr_len := (int(rest[1]) + 1) * 8
			if len(rest) < hdr_len {
				pkt.Error = "truncated ipv6 extension header"
				pkt.ErrorType = ErrTypeTruncatedPacket
				pkt.Payload = rest
				return
			}
			next_header = rest[0]
			rest = rest[hdr_len:]
		case 44: // fragment
			if len(rest) < 8 {
				pkt.Error = "truncated ipv6 fragment header"
				pkt.ErrorType = ErrTypeTruncatedPacket
				pkt.Payload = rest
				return
			}
			frag_field := binary.BigEndian.Uint16(rest[2:4])
			if frag_field&0xfff9 != 0 {
				// Non-first fragment - no transport header
				// available.
				pkt.Protocol = protocolName(next_headerOf(rest))
				pkt.Payload = rest[8:]
				return
			}
			next_header = rest[0]
			rest = rest[8:]
		case 51: // AH
			if len(rest) < 8 {
				pkt.Error = "truncated ipv6 ah header"
				pkt.ErrorType = ErrTypeTruncatedPacket
				pkt.Payload = rest
				return
			}
			hdr_len := (int(rest[1]) + 2) * 4
			if len(rest) < hdr_len {
				pkt.Error = "truncated ipv6 ah header"
				pkt.ErrorType = ErrTypeTruncatedPacket
				pkt.Payload = rest
				return
			}
			next_header = rest[0]
			rest = rest[hdr_len:]
		default:
			decodeTransport(pkt, 6, next_header, rest)
			return
		}
	}
}

func next_headerOf(fragment_header []byte) uint8 {
	return fragment_header[0]
}

func protocolName(proto uint8) string {
	switch proto {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 58:
		return "ICMPv6"
	default:
		return fmt.Sprintf("ip_proto_%d", proto)
	}
}

func decodeTransport(pkt *Packet, ip_version, proto uint8, data []byte) {
	pkt.Protocol = protocolName(proto)
	switch proto {
	case 6: // TCP
		if len(data) < 20 {
			pkt.Error = "truncated tcp header"
			pkt.ErrorType = ErrTypeTruncatedPacket
			pkt.Payload = data
			return
		}
		pkt.SrcPort = binary.BigEndian.Uint16(data[0:2])
		pkt.DstPort = binary.BigEndian.Uint16(data[2:4])
		data_offset := int(data[12]>>4) * 4
		if data_offset < 20 || len(data) < data_offset {
			pkt.Error = "truncated tcp options"
			pkt.ErrorType = ErrTypeTruncatedPacket
			pkt.Payload = data
			return
		}
		pkt.Payload = data[data_offset:]

	case 17: // UDP
		if len(data) < 8 {
			pkt.Error = "truncated udp header"
			pkt.ErrorType = ErrTypeTruncatedPacket
			pkt.Payload = data
			return
		}
		pkt.SrcPort = binary.BigEndian.Uint16(data[0:2])
		pkt.DstPort = binary.BigEndian.Uint16(data[2:4])
		pkt.Payload = data[8:]

	default:
		// ICMP and everything else - no ports, rest is payload.
		pkt.Payload = data
	}
}
