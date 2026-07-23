// Copyright 2026 The HuaTuo Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package filter

import (
	"encoding/binary"
	"errors"
	"testing"

	"golang.org/x/net/bpf"
)

type vlanTag struct {
	etherType uint16
	id        uint16
}

func addVLANTags(t *testing.T, packet []byte, tags ...vlanTag) []byte {
	t.Helper()
	if len(packet) < 14 {
		t.Fatalf("packet is shorter than an ethernet header: %d", len(packet))
	}
	result := make([]byte, len(packet)+4*len(tags))
	copy(result[:12], packet[:12])
	offset := 12
	for _, tag := range tags {
		binary.BigEndian.PutUint16(result[offset:offset+2], tag.etherType)
		binary.BigEndian.PutUint16(result[offset+2:offset+4], tag.id&0x0fff)
		offset += 4
	}
	copy(result[offset:], packet[12:])
	return result
}

func addMPLSLabels(t *testing.T, packet []byte, labels ...uint32) []byte {
	t.Helper()
	if len(packet) < 14 || len(labels) == 0 {
		t.Fatalf("invalid mpls fixture")
	}
	result := make([]byte, len(packet)+4*len(labels))
	copy(result[:12], packet[:12])
	binary.BigEndian.PutUint16(result[12:14], uint16(etherTypeMPLSUnicast))
	offset := 14
	for index, label := range labels {
		entry := (label & 0x000fffff) << 12
		if index == len(labels)-1 {
			entry |= 1 << 8
		}
		entry |= 64
		binary.BigEndian.PutUint32(result[offset:offset+4], entry)
		offset += 4
	}
	copy(result[offset:], packet[14:])
	return result
}

func TestCompileVLANCursor(t *testing.T) {
	t.Parallel()
	packets := behaviorPacketCorpus(t)
	single := addVLANTags(t, packets["ip4-tcp-80"], vlanTag{etherType: uint16(etherTypeVLAN), id: 100})
	double := addVLANTags(
		t,
		packets["ip4-tcp-80"],
		vlanTag{etherType: uint16(etherTypeQinQ), id: 100},
		vlanTag{etherType: uint16(etherTypeVLAN), id: 200},
	)

	tests := []struct {
		name     string
		expr     string
		packet   []byte
		expected bool
	}{
		{name: "single tag", expr: "vlan and tcp port 80", packet: single, expected: true},
		{name: "single tag id", expr: "vlan 100 and tcp port 80", packet: single, expected: true},
		{name: "wrong tag id", expr: "vlan 200 and tcp port 80", packet: single, expected: false},
		{name: "double tag", expr: "vlan and vlan and tcp port 80", packet: double, expected: true},
		{name: "double tag ids", expr: "vlan 100 and vlan 200 and tcp port 80", packet: double, expected: true},
		{name: "double tag arithmetic", expr: "vlan and vlan and ip[9] == 6", packet: double, expected: true},
		{name: "untagged rejected", expr: "vlan and tcp port 80", packet: packets["ip4-tcp-80"], expected: false},
		{
			name:     "or branch resets cursor",
			expr:     "(vlan and tcp port 80) or tcp port 443",
			packet:   packets["ip4-tcp-443"],
			expected: true,
		},
		{
			name:     "qualifier shorthand survives transition parser",
			expr:     "vlan and tcp dst port 80 or 443",
			packet:   packets["ip4-tcp-443"],
			expected: true,
		},
		{name: "or tagged branch", expr: "(vlan and tcp port 80) or tcp port 443", packet: single, expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := filterVerdict(t, tt.expr, LinkTypeEthernet, tt.packet); got != tt.expected {
				t.Fatalf("verdict = %v, expected %v", got, tt.expected)
			}
		})
	}
	if _, err := Compile("vlan and ip", LinkTypeRaw); !errors.Is(err, ErrL2OnlyLinkType) {
		t.Fatalf("raw vlan error = %v, expected ErrL2OnlyLinkType", err)
	}
}

func TestCompileMPLSCursor(t *testing.T) {
	t.Parallel()
	packets := behaviorPacketCorpus(t)
	one := addMPLSLabels(t, packets["ip4-tcp-80"], 100)
	two := addMPLSLabels(t, packets["ip6-udp-53"], 100, 200)

	tests := []struct {
		name     string
		expr     string
		packet   []byte
		expected bool
	}{
		{name: "one label ipv4", expr: "mpls and ip", packet: one, expected: true},
		{name: "label value", expr: "mpls 100 and tcp port 80", packet: one, expected: true},
		{name: "label arithmetic", expr: "mpls 100 and ip[9] == 6", packet: one, expected: true},
		{name: "wrong label value", expr: "mpls 101 and ip", packet: one, expected: false},
		{name: "two labels ipv6", expr: "mpls 100 and mpls 200 and ip6", packet: two, expected: true},
		{name: "missing second label", expr: "mpls and mpls and ip", packet: one, expected: false},
		{
			name:     "non-bottom label cannot expose ip",
			expr:     "mpls and ip",
			packet:   addMPLSLabelsWithoutBottom(t, packets["ip4-tcp-80"], 100),
			expected: false,
		},
		{
			name:     "non-bottom label still permits length checks",
			expr:     "mpls and len > 0",
			packet:   addMPLSLabelsWithoutBottom(t, packets["ip4-tcp-80"], 100),
			expected: true,
		},
		{name: "plain ethernet rejected", expr: "mpls and ip", packet: packets["ip4-tcp-80"], expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := filterVerdict(t, tt.expr, LinkTypeEthernet, tt.packet); got != tt.expected {
				t.Fatalf("verdict = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestCompilePacketArithmetic(t *testing.T) {
	t.Parallel()
	packets := behaviorPacketCorpus(t)
	syn := append([]byte(nil), packets["ip4-tcp-80"]...)
	syn[14+20+13] = 0x02
	withOptions := append([]byte(nil), syn...)
	withOptions[14] = 0x46
	withOptions = append(withOptions[:14+20], append([]byte{0, 0, 0, 0}, withOptions[14+20:]...)...)
	withOptions[14] = 0x46

	tests := []struct {
		name     string
		expr     string
		link     LinkType
		packet   []byte
		expected bool
	}{
		{name: "tcp syn flag", expr: "tcp[tcpflags] == tcp-syn", link: LinkTypeEthernet, packet: syn, expected: true},
		{
			name:     "tcp syn flag rejects ack",
			expr:     "tcp[tcpflags] == tcp-syn",
			link:     LinkTypeEthernet,
			packet:   packets["ip4-tcp-80"],
			expected: false,
		},
		{name: "ipv4 header length", expr: "ip[0] & 0x0f > 5", link: LinkTypeEthernet, packet: withOptions, expected: true},
		{name: "big endian half word", expr: "ether[12:2] == 0x0800", link: LinkTypeEthernet, packet: syn, expected: true},
		{name: "big endian word", expr: "ip[12:4] == 0x0a000001", link: LinkTypeEthernet, packet: syn, expected: true},
		{name: "dynamic offset", expr: "ip[4 * 2 + 1] == 6", link: LinkTypeEthernet, packet: syn, expected: true},
		{name: "raw byte access", expr: "ip[9] == 6", link: LinkTypeRaw, packet: rawBehaviorPacket(t, syn), expected: true},
		{name: "length comparison", expr: "len >= 40", link: LinkTypeRaw, packet: rawBehaviorPacket(t, syn), expected: true},
		{
			name:     "truncated access rejects",
			expr:     "tcp[tcpflags] == tcp-syn",
			link:     LinkTypeRaw,
			packet:   rawBehaviorPacket(t, syn)[:24],
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := filterVerdict(t, tt.expr, tt.link, tt.packet); got != tt.expected {
				t.Fatalf("verdict = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestCompilePacketArithmeticRejectsInvalidAccess(t *testing.T) {
	t.Parallel()

	for _, expr := range []string{
		"ip[0:3] == 0",
		"ip[] == 0",
		"ip[0] ==",
		"ip[0] / 0 == 1",
		"tcp[tcpflags]",
		"len",
	} {
		t.Run(expr, func(t *testing.T) {
			t.Parallel()
			_, err := Compile(expr, LinkTypeRaw)
			if err == nil {
				t.Fatalf("Compile(%q) succeeded", expr)
			}
		})
	}
}

func TestCompileRawRejectsEthernetPacketAccess(t *testing.T) {
	t.Parallel()

	_, err := Compile("ether[12:2] == 0x0800", LinkTypeRaw)
	if !errors.Is(err, ErrL2OnlyLinkType) {
		t.Fatalf("error = %v, expected ErrL2OnlyLinkType", err)
	}
}

func TestP0ProgramsAssembleToRawCBPF(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		expr string
		link LinkType
	}{
		{name: "port range", expr: "portrange 1000-2000", link: LinkTypeRaw},
		{name: "packet arithmetic", expr: "tcp[tcpflags] == tcp-syn", link: LinkTypeRaw},
		{name: "vlan", expr: "vlan and vlan and tcp port 80", link: LinkTypeEthernet},
		{name: "mpls", expr: "mpls and mpls and ip6", link: LinkTypeEthernet},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			instructions, err := Compile(tt.expr, tt.link)
			if err != nil {
				t.Fatalf("Compile(%q): %v", tt.expr, err)
			}
			if _, err := bpf.Assemble(instructions); err != nil {
				t.Fatalf("Assemble(%q): %v", tt.expr, err)
			}
		})
	}
}

func addMPLSLabelsWithoutBottom(t *testing.T, packet []byte, label uint32) []byte {
	t.Helper()
	result := addMPLSLabels(t, packet, label)
	result[16] &^= 0x01
	return result
}
