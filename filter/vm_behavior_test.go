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
	"net"
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
			&layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP,
				SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("192.0.2.10")},
			&layers.TCP{SrcPort: 1234, DstPort: 80, DataOffset: 5},
			gopacket.Payload([]byte("x"))),
		"ip4-tcp-443": serializeBehaviorPacket(t,
			eth(layers.EthernetTypeIPv4),
			&layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP,
				SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("192.0.2.11")},
			&layers.TCP{SrcPort: 1234, DstPort: 443, DataOffset: 5},
			gopacket.Payload([]byte("x"))),
		"ip4-udp-53": serializeBehaviorPacket(t,
			eth(layers.EthernetTypeIPv4),
			&layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP,
				SrcIP: net.ParseIP("10.0.0.2"), DstIP: net.ParseIP("10.0.0.3")},
			&layers.UDP{SrcPort: 53, DstPort: 9999},
			gopacket.Payload([]byte("x"))),
		"ip4-icmp": serializeBehaviorPacket(t,
			eth(layers.EthernetTypeIPv4),
			&layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolICMPv4,
				SrcIP: net.ParseIP("10.0.0.4"), DstIP: net.ParseIP("10.0.0.5")},
			&layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0)}),
		"ip4-self-udp": serializeBehaviorPacket(t,
			eth(layers.EthernetTypeIPv4),
			&layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP,
				SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.1")},
			&layers.UDP{SrcPort: 1000, DstPort: 1001},
			gopacket.Payload([]byte("x"))),
		"ip4-multicast": serializeBehaviorPacket(t,
			eth(layers.EthernetTypeIPv4),
			&layers.IPv4{Version: 4, IHL: 5, TTL: 1, Protocol: layers.IPProtocolUDP,
				SrcIP: net.ParseIP("10.0.0.7"), DstIP: net.ParseIP("224.0.0.1")},
			&layers.UDP{SrcPort: 1900, DstPort: 1900},
			gopacket.Payload([]byte("x"))),
		"ip6-udp-53": serializeBehaviorPacket(t,
			eth(layers.EthernetTypeIPv6),
			&layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolUDP,
				SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2")},
			&layers.UDP{SrcPort: 53, DstPort: 5353},
			gopacket.Payload([]byte("x"))),
		"arp-request": serializeBehaviorPacket(t,
			eth(layers.EthernetTypeARP),
			&layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
				HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPRequest,
				SourceHwAddress: srcMAC, SourceProtAddress: net.ParseIP("10.0.0.1").To4(),
				DstHwAddress: make([]byte, 6), DstProtAddress: net.ParseIP("10.0.0.9").To4()}),
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
