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
	"errors"
	"fmt"
	"net"
	"slices"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/net/bpf"
)

func serializeBehaviorPacket(t testing.TB, parts ...gopacket.SerializableLayer) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false}
	if err := gopacket.SerializeLayers(buf, opts, parts...); err != nil {
		t.Fatalf("serialize packet: %v", err)
	}
	return buf.Bytes()
}

func behaviorPacketCorpus(t testing.TB) map[string][]byte {
	t.Helper()
	srcMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	dstMAC, _ := net.ParseMAC("11:22:33:44:55:66")
	eth := func(etherType layers.EthernetType) *layers.Ethernet {
		return &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: etherType}
	}

	return map[string][]byte{
		"ip4-tcp-80": serializeBehaviorPacket(t,
			eth(layers.EthernetTypeIPv4),
			&layers.IPv4{
				Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP,
				SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("192.0.2.10"),
			},
			&layers.TCP{SrcPort: 1234, DstPort: 80, DataOffset: 5},
			gopacket.Payload([]byte("x"))),
		"ip4-tcp-443": serializeBehaviorPacket(t,
			eth(layers.EthernetTypeIPv4),
			&layers.IPv4{
				Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP,
				SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("192.0.2.11"),
			},
			&layers.TCP{SrcPort: 1234, DstPort: 443, DataOffset: 5},
			gopacket.Payload([]byte("x"))),
		"ip4-udp-53": serializeBehaviorPacket(t,
			eth(layers.EthernetTypeIPv4),
			&layers.IPv4{
				Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP,
				SrcIP: net.ParseIP("10.0.0.2"), DstIP: net.ParseIP("10.0.0.3"),
			},
			&layers.UDP{SrcPort: 53, DstPort: 9999},
			gopacket.Payload([]byte("x"))),
		"ip4-icmp": serializeBehaviorPacket(t,
			eth(layers.EthernetTypeIPv4),
			&layers.IPv4{
				Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolICMPv4,
				SrcIP: net.ParseIP("10.0.0.4"), DstIP: net.ParseIP("10.0.0.5"),
			},
			&layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0)}),
		"ip4-igmp": serializeBehaviorPacket(t,
			eth(layers.EthernetTypeIPv4),
			&layers.IPv4{
				Version: 4, IHL: 5, TTL: 1, Protocol: layers.IPProtocolIGMP,
				SrcIP: net.ParseIP("10.0.0.6"), DstIP: net.ParseIP("224.0.0.1"),
			},
			gopacket.Payload([]byte{0x11, 0x00, 0x00, 0x00})),
		"ip4-self-udp": serializeBehaviorPacket(t,
			eth(layers.EthernetTypeIPv4),
			&layers.IPv4{
				Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP,
				SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.1"),
			},
			&layers.UDP{SrcPort: 1000, DstPort: 1001},
			gopacket.Payload([]byte("x"))),
		"ip4-multicast": serializeBehaviorPacket(t,
			eth(layers.EthernetTypeIPv4),
			&layers.IPv4{
				Version: 4, IHL: 5, TTL: 1, Protocol: layers.IPProtocolUDP,
				SrcIP: net.ParseIP("10.0.0.7"), DstIP: net.ParseIP("224.0.0.1"),
			},
			&layers.UDP{SrcPort: 1900, DstPort: 1900},
			gopacket.Payload([]byte("x"))),
		"ip6-udp-53": serializeBehaviorPacket(t,
			eth(layers.EthernetTypeIPv6),
			&layers.IPv6{
				Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolUDP,
				SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2"),
			},
			&layers.UDP{SrcPort: 53, DstPort: 5353},
			gopacket.Payload([]byte("x"))),
		"ip6-tcp-80": serializeBehaviorPacket(t,
			eth(layers.EthernetTypeIPv6),
			&layers.IPv6{
				Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolTCP,
				SrcIP: net.ParseIP("2001:db8::10"), DstIP: net.ParseIP("2001:db8::20"),
			},
			&layers.TCP{SrcPort: 1234, DstPort: 80, DataOffset: 5},
			gopacket.Payload([]byte("x"))),
		"ip6-tcp-443": serializeBehaviorPacket(t,
			eth(layers.EthernetTypeIPv6),
			&layers.IPv6{
				Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolTCP,
				SrcIP: net.ParseIP("2001:db8::10"), DstIP: net.ParseIP("2001:db8::21"),
			},
			&layers.TCP{SrcPort: 1234, DstPort: 443, DataOffset: 5},
			gopacket.Payload([]byte("x"))),
		"ip6-icmp6": serializeBehaviorPacket(t,
			eth(layers.EthernetTypeIPv6),
			&layers.IPv6{
				Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolICMPv6,
				SrcIP: net.ParseIP("2001:db8::30"), DstIP: net.ParseIP("2001:db8::31"),
			},
			&layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0)}),
		"ip6-udp-80": serializeBehaviorPacket(t,
			eth(layers.EthernetTypeIPv6),
			&layers.IPv6{
				Version:    6,
				HopLimit:   64,
				NextHeader: layers.IPProtocolUDP,
				SrcIP:      net.ParseIP("2001:db8::10"),
				DstIP:      net.ParseIP("2001:db8::20"),
			},
			&layers.UDP{
				SrcPort: 1234,
				DstPort: 80,
			}),
		"ip4-sctp-80": serializeBehaviorPacket(t,
			eth(layers.EthernetTypeIPv4),
			&layers.IPv4{
				Version:  4,
				IHL:      5,
				TTL:      64,
				Protocol: layers.IPProtocolSCTP,
				SrcIP:    net.ParseIP("10.0.0.1"),
				DstIP:    net.ParseIP("192.0.2.10"),
			},
			&layers.SCTP{
				SrcPort: 1234,
				DstPort: 80,
			}),
		"ip6-sctp-80": serializeBehaviorPacket(t,
			eth(layers.EthernetTypeIPv6),
			&layers.IPv6{
				Version:    6,
				HopLimit:   64,
				NextHeader: layers.IPProtocolSCTP,
				SrcIP:      net.ParseIP("2001:db8::10"),
				DstIP:      net.ParseIP("2001:db8::20"),
			},
			&layers.SCTP{
				SrcPort: 1234,
				DstPort: 80,
			}),
		"arp-request": serializeBehaviorPacket(t,
			eth(layers.EthernetTypeARP),
			&layers.ARP{
				AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
				HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPRequest,
				SourceHwAddress: srcMAC, SourceProtAddress: net.ParseIP("10.0.0.1").To4(),
				DstHwAddress: make([]byte, 6), DstProtAddress: net.ParseIP("10.0.0.9").To4(),
			}),
		"rarp-request": serializeBehaviorPacket(t,
			eth(layers.EthernetType(etherTypeRarp)),
			&layers.ARP{
				AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
				HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPRequest,
				SourceHwAddress: srcMAC, SourceProtAddress: net.ParseIP("10.0.0.1").To4(),
				DstHwAddress: make([]byte, 6), DstProtAddress: net.ParseIP("10.0.0.9").To4(),
			}),
	}
}

func rawBehaviorPacket(t testing.TB, ethernetPacket []byte) []byte {
	t.Helper()
	if len(ethernetPacket) < 14 {
		t.Fatalf("packet is shorter than an ethernet header: %d", len(ethernetPacket))
	}
	return ethernetPacket[14:]
}

func TestCompiledFiltersClassifyPackets(t *testing.T) {
	packets := behaviorPacketCorpus(t)
	nonFirstFragment := make([]byte, 40)
	nonFirstFragment[0] = 0x45
	nonFirstFragment[6], nonFirstFragment[7] = 0, 1
	nonFirstFragment[9] = byte(layers.IPProtocolTCP)
	nonFirstFragment[20], nonFirstFragment[21] = 0, 80
	nonFirstFragment[22], nonFirstFragment[23] = 0, 80

	tests := []struct {
		name   string
		expr   string
		link   LinkType
		packet []byte
		accept bool
	}{
		{"ethernet bare ip accepts IPv4", "ip", LinkTypeEthernet, packets["ip4-tcp-80"], true},
		{"ethernet bare ip rejects IPv6", "ip", LinkTypeEthernet, packets["ip6-udp-53"], false},
		{"ethernet precedence accepts TCP port 80", "tcp and port 80 or udp", LinkTypeEthernet, packets["ip4-tcp-80"], true},
		{"ethernet precedence rejects TCP port 443", "tcp and port 80 or udp", LinkTypeEthernet, packets["ip4-tcp-443"], false},
		{"ethernet precedence accepts UDP", "tcp and port 80 or udp", LinkTypeEthernet, packets["ip4-udp-53"], true},
		{"ethernet negation rejects TCP", "not tcp", LinkTypeEthernet, packets["ip4-tcp-80"], false},
		{"ethernet negated braces accept ICMP", "not (tcp or udp)", LinkTypeEthernet, packets["ip4-icmp"], true},
		{"ethernet both directions require both matches", "src and dst host 10.0.0.1", LinkTypeEthernet, packets["ip4-self-udp"], true},
		{"ethernet both directions reject one match", "src and dst host 10.0.0.1", LinkTypeEthernet, packets["ip4-tcp-80"], false},
		{"ethernet IP multicast", "ip multicast", LinkTypeEthernet, packets["ip4-multicast"], true},
		{"ethernet ARP", "arp", LinkTypeEthernet, packets["arp-request"], true},
		{"raw precedence accepts TCP port 80", "tcp and port 80 or udp", LinkTypeRaw, rawBehaviorPacket(t, packets["ip4-tcp-80"]), true},
		{"raw precedence rejects TCP port 443", "tcp and port 80 or udp", LinkTypeRaw, rawBehaviorPacket(t, packets["ip4-tcp-443"]), false},
		{"raw precedence accepts UDP", "tcp and port 80 or udp", LinkTypeRaw, rawBehaviorPacket(t, packets["ip4-udp-53"]), true},
		{"raw IPv6 UDP port", "ip6 and udp and port 53", LinkTypeRaw, rawBehaviorPacket(t, packets["ip6-udp-53"]), true},
		{"raw IP multicast", "ip multicast", LinkTypeRaw, rawBehaviorPacket(t, packets["ip4-multicast"]), true},
		{"raw non-first fragment cannot match port", "tcp and port 80", LinkTypeRaw, nonFirstFragment, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			insns, err := Compile(tt.expr, tt.link)
			if err != nil {
				t.Fatalf("Compile(%q): %v", tt.expr, err)
			}
			vm, err := bpf.NewVM(insns)
			if err != nil {
				t.Fatalf("NewVM(%q): %v", tt.expr, err)
			}
			out, err := vm.Run(tt.packet)
			if err != nil {
				t.Fatalf("Run(%q): %v", tt.expr, err)
			}
			if got := out != 0; got != tt.accept {
				t.Errorf("accept=%v, want %v (return=%d)", got, tt.accept, out)
			}
		})
	}
}

func TestCompiledBooleanGroups(t *testing.T) {
	packets := behaviorPacketCorpus(t)
	tests := []struct {
		expr      string
		acceptAll bool
		accepted  []string
	}{
		{expr: "arp and tcp"},
		{expr: "(arp) and tcp"},
		{expr: "((arp or tcp)) and udp"},
		{
			expr:     "(arp)",
			accepted: []string{"arp-request"},
		},
		{
			expr:     "((arp and arp))",
			accepted: []string{"arp-request"},
		},
		{
			expr:     "(arp and arp) or (tcp and not (arp))",
			accepted: []string{"arp-request", "ip4-tcp-80", "ip6-tcp-80", "ip4-tcp-443", "ip6-tcp-443"},
		},
		{
			expr:     "not ((arp)) and (udp)",
			accepted: []string{"ip4-udp-53", "ip6-udp-53"},
		},
		{
			expr:     "(port 80) or 443",
			accepted: []string{"ip4-tcp-80", "ip6-tcp-80", "ip4-tcp-443", "ip6-tcp-443"},
		},
		{expr: "tcp and arp"},
		{expr: "rarp and udp"},
		{expr: "arp and port 80"},
		{expr: "(arp or tcp) and udp"},
		{
			expr:      "not (arp and tcp)",
			acceptAll: true,
		},
		{
			expr:      "not ((arp or tcp) and udp)",
			acceptAll: true,
		},
		{
			expr:     "arp or (tcp and udp)",
			accepted: []string{"arp-request"},
		},
		{
			expr:     "(arp and tcp) or udp",
			accepted: []string{"ip4-udp-53", "ip6-udp-53"},
		},
		{
			expr:     "(arp or tcp) and port 80",
			accepted: []string{"ip4-tcp-80", "ip6-tcp-80"},
		},
		{
			expr:     "tcp and (port 80 or port 443) and not port 443",
			accepted: []string{"ip4-tcp-80", "ip6-tcp-80"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			rawRejectAll := !tt.acceptAll
			for _, name := range tt.accepted {
				if name != "arp-request" && name != "rarp-request" {
					rawRejectAll = false
					break
				}
			}

			for _, linkType := range []LinkType{LinkTypeEthernet, LinkTypeRaw} {
				for _, target := range []CompileTarget{CompileTargetPortable, CompileTargetLinuxSocket} {
					instructions, err := CompileWithOptions(tt.expr, CompileOptions{
						LinkType: linkType,
						Target:   target,
					})
					// The public raw-IP API reports L2-only reject-all programs
					// through its existing sentinel, rather than returning bytecode.
					if linkType == LinkTypeRaw && rawRejectAll && errors.Is(err, ErrL2OnlyLinkType) {
						continue
					}

					if err != nil {
						t.Fatalf("link %v target %v: %v", linkType, target, err)
					}

					vm, err := bpf.NewVM(instructions)
					if err != nil {
						t.Fatal(err)
					}

					for _, name := range []string{"ip4-tcp-80", "ip6-tcp-80", "ip4-tcp-443", "ip6-tcp-443", "ip4-udp-53", "ip6-udp-53", "arp-request", "rarp-request"} {
						packet := packets[name]
						if linkType == LinkTypeRaw {
							if name == "arp-request" || name == "rarp-request" {
								continue
							}

							packet = rawBehaviorPacket(t, packet)
						}

						out, err := vm.Run(packet)
						if err != nil {
							t.Fatal(err)
						}

						want := tt.acceptAll || slices.Contains(tt.accepted, name)
						if (out != 0) != want {
							t.Errorf("link %v target %v packet %s: accept=%t, want %t", linkType, target, name, out != 0, want)
						}
					}
				}
			}
		})
	}
}

func TestCompileRejectsInvalidCombinedQualifiers(t *testing.T) {
	for _, expression := range []string{"arp tcp", "rarp udp", "arp port 80", "ether tcp"} {
		t.Run(expression, func(t *testing.T) {
			for _, linkType := range []LinkType{LinkTypeEthernet, LinkTypeRaw} {
				if _, err := Compile(expression, linkType); !errors.Is(err, ErrInvalidFilter) {
					t.Fatalf("Compile(%q, %v)=%v, want ErrInvalidFilter", expression, linkType, err)
				}
			}
		})
	}
}

func TestCompiledProtocolQualifiedAddresses(t *testing.T) {
	packets := behaviorPacketCorpus(t)
	cases := map[string][]string{
		"tcp src host 10.0.0.1":                            {"ip4-tcp-80", "ip4-tcp-443"},
		"tcp dst host 192.0.2.10":                          {"ip4-tcp-80"},
		"tcp src net 10.0.0.0/24":                          {"ip4-tcp-80", "ip4-tcp-443"},
		"tcp dst net 192.0.2.0/24":                         {"ip4-tcp-80", "ip4-tcp-443"},
		"udp src host 10.0.0.1":                            {"ip4-self-udp"},
		"udp dst host 10.0.0.1":                            {"ip4-self-udp"},
		"udp src net 10.0.0.0/24":                          {"ip4-udp-53", "ip4-self-udp", "ip4-multicast"},
		"udp dst net 10.0.0.0/24":                          {"ip4-udp-53", "ip4-self-udp"},
		"tcp src host 2001:db8::10":                        {"ip6-tcp-80", "ip6-tcp-443"},
		"tcp dst host 2001:db8::20":                        {"ip6-tcp-80"},
		"tcp src net 2001:db8::/64":                        {"ip6-tcp-80", "ip6-tcp-443"},
		"tcp dst net 2001:db8::/64":                        {"ip6-tcp-80", "ip6-tcp-443"},
		"udp src host 2001:db8::10":                        {"ip6-udp-80"},
		"udp dst host 2001:db8::20":                        {"ip6-udp-80"},
		"udp src net 2001:db8::/64":                        {"ip6-udp-53", "ip6-udp-80"},
		"udp dst net 2001:db8::/64":                        {"ip6-udp-53", "ip6-udp-80"},
		"sctp src host 10.0.0.1":                           {"ip4-sctp-80"},
		"sctp dst host 192.0.2.10":                         {"ip4-sctp-80"},
		"sctp src net 10.0.0.0/24":                         {"ip4-sctp-80"},
		"sctp dst net 192.0.2.0/24":                        {"ip4-sctp-80"},
		"sctp src host 2001:db8::10":                       {"ip6-sctp-80"},
		"sctp dst host 2001:db8::20":                       {"ip6-sctp-80"},
		"sctp src net 2001:db8::/64":                       {"ip6-sctp-80"},
		"sctp dst net 2001:db8::/64":                       {"ip6-sctp-80"},
		"tcp src host 203.0.113.1":                         nil,
		"udp src net 203.0.113.0/24":                       nil,
		"tcp dst host 2001:db9::1":                         nil,
		"udp dst net 2001:db9::/64":                        nil,
		"port 80 and tcp src host 10.0.0.1":                {"ip4-tcp-80"},
		"udp src host 10.0.0.1 or tcp dst host 192.0.2.10": {"ip4-self-udp", "ip4-tcp-80"},
	}

	for expression, accepted := range cases {
		t.Run(expression, func(t *testing.T) {
			assertCompiledBehavior(t, expression, packets, accepted)
		})
	}
}

func TestCompiledSCTPProtocols(t *testing.T) {
	packets := behaviorPacketCorpus(t)
	cases := map[string][]string{
		"sctp":           {"ip4-sctp-80", "ip6-sctp-80"},
		"ip proto sctp":  {"ip4-sctp-80"},
		"ip6 proto sctp": {"ip6-sctp-80"},
		"sctp port 80":   {"ip4-sctp-80", "ip6-sctp-80"},
	}

	for expression, accepted := range cases {
		t.Run(expression, func(t *testing.T) {
			assertCompiledBehavior(t, expression, packets, accepted)
		})
	}
}

func assertCompiledBehavior(t *testing.T, expression string, packets map[string][]byte, accepted []string) {
	t.Helper()

	for _, link := range []LinkType{LinkTypeEthernet, LinkTypeRaw} {
		for _, target := range []CompileTarget{CompileTargetPortable, CompileTargetLinuxSocket} {
			t.Run(fmt.Sprintf("link-%d/target-%d", link, target), func(t *testing.T) {
				instructions, err := CompileWithOptions(expression, CompileOptions{
					LinkType: link,
					Target:   target,
				})
				if err != nil {
					t.Fatal(err)
				}

				vm, err := bpf.NewVM(instructions)
				if err != nil {
					t.Fatal(err)
				}

				for name, frame := range packets {
					if link == LinkTypeRaw {
						if name == "arp-request" || name == "rarp-request" {
							continue
						}

						frame = rawBehaviorPacket(t, frame)
					}

					verdict, err := vm.Run(frame)
					want := slices.Contains(accepted, name)
					if err != nil || (verdict != 0) != want {
						t.Errorf("packet %s: verdict=%d error=%v, want accept=%t", name, verdict, err, want)
					}
				}
			})
		}
	}
}
