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
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"golang.org/x/net/bpf"
)

type staticResolver struct {
	addrs []string
	err   error
}

func (r staticResolver) LookupHost(context.Context, string) ([]string, error) {
	return r.addrs, r.err
}

func rawIPv4Ports(protocol byte, source, destination uint16) []byte {
	packet := rawIPv4Protocol(protocol)
	packet[20], packet[21] = byte(source>>8), byte(source)
	packet[22], packet[23] = byte(destination>>8), byte(destination)
	return packet
}

func TestCompilePortRange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		expr     string
		packet   []byte
		expected bool
	}{
		{name: "source lower bound", expr: "src portrange 1000-2000", packet: rawIPv4Ports(6, 1000, 80), expected: true},
		{name: "source upper bound", expr: "src portrange 1000-2000", packet: rawIPv4Ports(6, 2000, 80), expected: true},
		{name: "source below range", expr: "src portrange 1000-2000", packet: rawIPv4Ports(6, 999, 1500), expected: false},
		{name: "destination in range", expr: "dst portrange 1000-2000", packet: rawIPv4Ports(17, 80, 1500), expected: true},
		{name: "either direction", expr: "portrange 1000-2000", packet: rawIPv4Ports(132, 80, 1500), expected: true},
		{
			name:     "both directions",
			expr:     "src and dst portrange 1000-2000",
			packet:   rawIPv4Ports(6, 1000, 2000),
			expected: true,
		},
		{
			name:     "both directions rejects one miss",
			expr:     "src and dst portrange 1000-2000",
			packet:   rawIPv4Ports(6, 1000, 2001),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := filterVerdict(t, tt.expr, LinkTypeRaw, tt.packet); got != tt.expected {
				t.Fatalf("verdict = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestCompilePortRangeRejectsInvalidRange(t *testing.T) {
	t.Parallel()

	for _, expr := range []string{"portrange 2000-1000", "portrange 1000", "portrange 0-70000"} {
		t.Run(expr, func(t *testing.T) {
			t.Parallel()
			if _, err := Compile(expr, LinkTypeRaw); err == nil {
				t.Fatalf("Compile(%q) succeeded", expr)
			}
		})
	}
}

func TestCompileSCTPAndSTP(t *testing.T) {
	t.Parallel()

	if !filterVerdict(t, "sctp", LinkTypeRaw, rawIPv4Protocol(byte(ipProtocolSctp))) {
		t.Fatal("sctp rejected an sctp packet")
	}
	if filterVerdict(t, "sctp", LinkTypeRaw, rawIPv4Protocol(byte(ipProtocolTCP))) {
		t.Fatal("sctp accepted a tcp packet")
	}

	stp := make([]byte, 18)
	stp[12], stp[13] = 0, 38
	stp[14], stp[15], stp[16] = 0x42, 0x42, 0x03
	if !filterVerdict(t, "stp", LinkTypeEthernet, stp) {
		t.Fatal("stp rejected an ieee 802.1d frame")
	}
	nonSTP := append([]byte(nil), stp...)
	nonSTP[14] = 0x43
	if filterVerdict(t, "stp", LinkTypeEthernet, nonSTP) {
		t.Fatal("stp accepted a non-stp llc frame")
	}
	if _, err := Compile("stp", LinkTypeRaw); !errors.Is(err, ErrL2OnlyLinkType) {
		t.Fatalf("Compile(stp, raw) error = %v, expected ErrL2OnlyLinkType", err)
	}
}

func TestCompileMatchesEveryResolvedHostAddress(t *testing.T) {
	t.Parallel()

	resolver := staticResolver{addrs: []string{
		"192.0.2.1",
		"203.0.113.5",
		"2001:db8::1",
		"2001:db8::2",
	}}
	insns, err := CompileWithOptions("host example.test", CompileOptions{
		LinkType: LinkTypeRaw,
		Resolver: resolver,
	})
	if err != nil {
		t.Fatalf("CompileWithOptions: %v", err)
	}

	tests := []struct {
		name     string
		packet   []byte
		expected bool
	}{
		{name: "first ipv4", packet: rawIPHostPacket(t, "192.0.2.1"), expected: true},
		{name: "second ipv4", packet: rawIPHostPacket(t, "203.0.113.5"), expected: true},
		{name: "first ipv6", packet: rawIPHostPacket(t, "2001:db8::1"), expected: true},
		{name: "second ipv6", packet: rawIPHostPacket(t, "2001:db8::2"), expected: true},
		{name: "unresolved address", packet: rawIPHostPacket(t, "198.51.100.8"), expected: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := runInstructions(t, insns, tt.packet); got != tt.expected {
				t.Fatalf("verdict = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestCompileHostResolutionErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		resolver Resolver
	}{
		{name: "lookup failure", resolver: staticResolver{err: errors.New("lookup failed")}},
		{name: "no addresses", resolver: staticResolver{addrs: []string{}}},
		{name: "invalid addresses", resolver: staticResolver{addrs: []string{"invalid"}}},
		{name: "wrong address family", resolver: staticResolver{addrs: []string{"2001:db8::1"}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := CompileWithOptions("ip host example.test", CompileOptions{
				LinkType: LinkTypeRaw,
				Resolver: tt.resolver,
			})
			if !errors.Is(err, ErrHostResolution) {
				t.Fatalf("error = %v, expected ErrHostResolution", err)
			}
		})
	}
}

func TestCompileFailsClosedForUnsupportedFeatures(t *testing.T) {
	t.Parallel()

	for _, expr := range []string{
		"gateway example.test",
		"fddi host 192.0.2.1",
		"wlan host 192.0.2.1",
		"atalk",
		"icmp port 80",
		"ip proto 132",
		"ip protochain tcp",
		"broadcast",
		"inbound",
		"outbound",
		"ifindex 2",
		"ip proto stp",
		"ip6 proto icmp",
		"ether proto tcp",
		"arp proto tcp",
		"stp host 192.0.2.1",
		"ether net 192.0.2.0/24",
	} {
		t.Run(expr, func(t *testing.T) {
			t.Parallel()
			_, err := Compile(expr, LinkTypeEthernet)
			if !errors.Is(err, ErrUnsupportedFeature) {
				t.Fatalf("error = %v, expected ErrUnsupportedFeature", err)
			}
		})
	}
}

func TestCompileRejectsMismatchedNetworkFamilies(t *testing.T) {
	t.Parallel()

	for _, expr := range []string{
		"ip6 net 192.0.2.0/24",
		"ip net 2001:db8::/32",
		"arp net 2001:db8::/32",
	} {
		t.Run(expr, func(t *testing.T) {
			t.Parallel()
			if _, err := Compile(expr, LinkTypeEthernet); !errors.Is(err, ErrInvalidFilter) {
				t.Fatalf("error = %v, expected ErrInvalidFilter", err)
			}
		})
	}
}

func TestCompileRejectsExcessiveInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		expr string
	}{
		{
			name: "expression length",
			expr: strings.Repeat("x", maxFilterExpressionLength+1),
		},
		{
			name: "nesting depth",
			expr: strings.Repeat("(", maxFilterNesting+1) + "ip" +
				strings.Repeat(")", maxFilterNesting+1),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := Compile(tt.expr, LinkTypeEthernet); !errors.Is(err, ErrInvalidFilter) {
				t.Fatalf("error = %v, expected ErrInvalidFilter", err)
			}
		})
	}
}

func FuzzCompileDoesNotPanic(f *testing.F) {
	for _, expression := range []string{
		"tcp port 80",
		"portrange 1000-2000",
		"vlan and vlan and ip[0] & 0x0f > 5",
		"mpls 100 and mpls 200 and ip6",
		"tcp[tcpflags] == tcp-syn",
		"not ((ip or ip6) and len >= 40)",
	} {
		f.Add(expression, uint8(LinkTypeEthernet))
	}

	f.Fuzz(func(t *testing.T, expression string, rawLinkType uint8) {
		linkType := LinkType(rawLinkType % 2)
		_, err := CompileWithOptions(expression, CompileOptions{
			LinkType: linkType,
			Resolver: staticResolver{err: errors.New("not found")},
		})
		if err != nil {
			return
		}
	})
}

func rawIPHostPacket(t *testing.T, source string) []byte {
	t.Helper()
	addr := net.ParseIP(source)
	if addr == nil {
		t.Fatalf("invalid test address %q", source)
	}
	if addr4 := addr.To4(); addr4 != nil {
		packet := rawIPv4Protocol(byte(ipProtocolUDP))
		copy(packet[12:16], addr4)
		return packet
	}
	packet := rawIPv6Protocol(byte(ipProtocolUDP))
	copy(packet[8:24], addr.To16())
	return packet
}

func runInstructions(t *testing.T, instructions []bpf.Instruction, packet []byte) bool {
	t.Helper()
	vm, err := bpf.NewVM(instructions)
	if err != nil {
		t.Fatalf("NewVM: %v", err)
	}
	result, err := vm.Run(packet)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return result != 0
}
