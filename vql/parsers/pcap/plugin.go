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
	"context"
	"encoding/hex"
	"io"
	"strings"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/velociraptor/accessors"
	"www.velocidex.com/golang/velociraptor/acls"
	vql_subsystem "www.velocidex.com/golang/velociraptor/vql"
	vfilter "www.velocidex.com/golang/vfilter"
	"www.velocidex.com/golang/vfilter/arg_parser"
)

const defaultPayloadBytes = 64

type ParsePcapPluginArgs struct {
	Filename *accessors.OSPath `vfilter:"required,field=filename,doc=The pcap or pcapng file to parse."`
	Accessor string            `vfilter:"optional,field=accessor,doc=The accessor to use."`
	Protocol string            `vfilter:"optional,field=protocol,doc=Only emit packets with this protocol (e.g. tcp, udp, icmp)."`
	Port     int64             `vfilter:"optional,field=port,doc=Only emit packets with this source or destination port."`
	Limit    int64             `vfilter:"optional,field=limit,doc=Maximum number of packets to emit (0 for no limit)."`
	Payload  int64             `vfilter:"optional,field=payload_bytes,doc=Maximum number of payload bytes to include per packet (default 64)."`
}

type ParsePcapPlugin struct{}

func (self ParsePcapPlugin) Info(
	scope vfilter.Scope, type_map *vfilter.TypeMap) *vfilter.PluginInfo {
	return &vfilter.PluginInfo{
		Name: "parse_pcap",
		Doc: "Parse a pcap or pcapng capture file, emitting one row per " +
			"packet with its timestamp, link type, 5-tuple, length and a " +
			"truncated payload. Corrupt records are reported as rows with " +
			"Error and ErrorType fields and do not abort parsing.",
		ArgType: type_map.AddType(scope, &ParsePcapPluginArgs{}),
		Metadata: vql_subsystem.VQLMetadata().Permissions(
			acls.FILESYSTEM_READ).Build(),
	}
}

func matchesFilter(arg *ParsePcapPluginArgs, pkt *Packet) bool {
	if arg.Protocol != "" &&
		!strings.EqualFold(pkt.Protocol, arg.Protocol) {
		return false
	}
	if arg.Port != 0 &&
		int64(pkt.SrcPort) != arg.Port && int64(pkt.DstPort) != arg.Port {
		return false
	}
	return true
}

func (self ParsePcapPlugin) Call(
	ctx context.Context, scope vfilter.Scope,
	args *ordereddict.Dict) <-chan vfilter.Row {
	output_chan := make(chan vfilter.Row)

	go func() {
		defer close(output_chan)
		defer vql_subsystem.RegisterMonitor(ctx, "parse_pcap", args)()

		err := vql_subsystem.CheckAccess(scope, acls.FILESYSTEM_READ)
		if err != nil {
			scope.Log("parse_pcap: %s", err)
			return
		}

		arg := &ParsePcapPluginArgs{}
		err = arg_parser.ExtractArgsWithContext(ctx, scope, args, arg)
		if err != nil {
			scope.Log("parse_pcap: %s", err.Error())
			return
		}

		accessor, err := accessors.GetAccessor(arg.Accessor, scope)
		if err != nil {
			scope.Log("parse_pcap: %v", err)
			return
		}

		fd, err := accessor.OpenWithOSPath(arg.Filename)
		if err != nil {
			scope.Log("parse_pcap: unable to open %s: %v",
				arg.Filename, err)
			return
		}
		defer fd.Close()

		reader, err := NewReader(fd)
		if err != nil {
			// An unreadable file header is reported as a single
			// error row so queries can still distinguish it.
			row := ordereddict.NewDict().
				Set("Error", err.Error()).
				Set("ErrorType", ErrTypeCorruptHeader)
			select {
			case <-ctx.Done():
			case output_chan <- row:
			}
			return
		}

		max_payload := arg.Payload
		if max_payload <= 0 {
			max_payload = defaultPayloadBytes
		}

		var emitted int64
		for {
			pkt, err := reader.Next()
			if err == io.EOF {
				return
			}
			if err != nil {
				scope.Log("parse_pcap: %v", err)
				return
			}

			if pkt.ErrorType == "" && !matchesFilter(arg, pkt) {
				continue
			}

			row := ordereddict.NewDict()
			if pkt.ErrorType != "" {
				row.Set("Error", pkt.Error).
					Set("ErrorType", pkt.ErrorType)
				if pkt.CapLength > 0 {
					row.Set("CapLength", pkt.CapLength)
				}
				if pkt.Length > 0 {
					row.Set("Length", pkt.Length)
				}
				// Undecodable frames still expose their raw
				// bytes so no data is lost.
				if len(pkt.Payload) > 0 {
					payload := pkt.Payload
					if int64(len(payload)) > max_payload {
						payload = payload[:max_payload]
					}
					row.Set("Payload", hex.EncodeToString(payload))
				}
			} else {
				row.Set("Timestamp", pkt.Timestamp).
					Set("LinkType", LinkTypeName(pkt.LinkType)).
					Set("SrcIP", pkt.SrcIP).
					Set("DstIP", pkt.DstIP).
					Set("SrcPort", pkt.SrcPort).
					Set("DstPort", pkt.DstPort).
					Set("Protocol", pkt.Protocol).
					Set("Length", pkt.Length).
					Set("CapLength", pkt.CapLength)

				payload := pkt.Payload
				if int64(len(payload)) > max_payload {
					payload = payload[:max_payload]
				}
				row.Set("Payload", hex.EncodeToString(payload))
			}

			select {
			case <-ctx.Done():
				return
			case output_chan <- row:
			}

			// The limit applies to packet rows - error rows are
			// always delivered.
			if pkt.ErrorType == "" {
				emitted++
				if arg.Limit > 0 && emitted >= arg.Limit {
					return
				}
			}
		}
	}()

	return output_chan
}

func init() {
	vql_subsystem.RegisterPlugin(&ParsePcapPlugin{})
}
