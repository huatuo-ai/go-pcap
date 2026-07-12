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

// Transitional bridge suite: while the legacy skip-counting generator and the
// label-based engine coexist, compile every expression with both and assert
// that they accept/reject the same packets in the BPF VM. Retired when the
// public API switches to the label engine and the case tables take over.

func serializePacket(t *testing.T, ls ...gopacket.SerializableLayer) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false}
	if err := gopacket.SerializeLayers(buf, opts, ls...); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return buf.Bytes()
}

func bridgePackets(t *testing.T) map[string][]byte {
	t.Helper()
	srcMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	dstMAC, _ := net.ParseMAC("11:22:33:44:55:66")

	eth := func(et layers.EthernetType) *layers.Ethernet {
		return &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: et}
	}

	return map[string][]byte{
		"ip4-tcp-80": serializePacket(t,
			eth(layers.EthernetTypeIPv4),
			&layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP,
				SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("192.168.1.5")},
			&layers.TCP{SrcPort: 1234, DstPort: 80, DataOffset: 5},
			gopacket.Payload([]byte("x"))),
		"ip4-udp-53": serializePacket(t,
			eth(layers.EthernetTypeIPv4),
			&layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP,
				SrcIP: net.ParseIP("10.0.0.2"), DstIP: net.ParseIP("10.0.0.3")},
			&layers.UDP{SrcPort: 53, DstPort: 9999},
			gopacket.Payload([]byte("x"))),
		"ip6-tcp-443": serializePacket(t,
			eth(layers.EthernetTypeIPv6),
			&layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolTCP,
				SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2")},
			&layers.TCP{SrcPort: 443, DstPort: 8080, DataOffset: 5},
			gopacket.Payload([]byte("x"))),
		"ip6-udp": serializePacket(t,
			eth(layers.EthernetTypeIPv6),
			&layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolUDP,
				SrcIP: net.ParseIP("2001:db8::10"), DstIP: net.ParseIP("2001:db8::20")},
			&layers.UDP{SrcPort: 5353, DstPort: 5353},
			gopacket.Payload([]byte("x"))),
		"arp-req": serializePacket(t,
			eth(layers.EthernetTypeARP),
			&layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
				HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPRequest,
				SourceHwAddress: srcMAC, SourceProtAddress: net.ParseIP("10.0.0.1").To4(),
				DstHwAddress: make([]byte, 6), DstProtAddress: net.ParseIP("10.0.0.9").To4()}),
		"ip4-mcast-udp": serializePacket(t,
			eth(layers.EthernetTypeIPv4),
			&layers.IPv4{Version: 4, IHL: 5, TTL: 1, Protocol: layers.IPProtocolUDP,
				SrcIP: net.ParseIP("10.0.0.7"), DstIP: net.ParseIP("224.0.0.1")},
			&layers.UDP{SrcPort: 1900, DstPort: 1900},
			gopacket.Payload([]byte("x"))),
		"non-ip": serializePacket(t,
			eth(layers.EthernetTypeLinkLayerDiscovery),
			gopacket.Payload([]byte{0x00, 0x01, 0x02, 0x03})),
	}
}

// legacyBroken lists expressions for which the legacy generator emits
// programs with out-of-bounds jumps - bpf.NewVM (and the kernel) refuse to
// load them, so there is no legacy verdict to compare against. For these the
// label engine is checked against hand-derived expectations instead.
var legacyBroken = map[string]map[string]bool{
	"ip": {
		"ip4-tcp-80": true, "ip4-udp-53": true, "ip4-mcast-udp": true,
		"ip6-tcp-443": false, "ip6-udp": false, "arp-req": false, "non-ip": false,
	},
	"ip6": {
		"ip4-tcp-80": false, "ip4-udp-53": false, "ip4-mcast-udp": false,
		"ip6-tcp-443": true, "ip6-udp": true, "arp-req": false, "non-ip": false,
	},
	"arp": {
		"ip4-tcp-80": false, "ip4-udp-53": false, "ip4-mcast-udp": false,
		"ip6-tcp-443": false, "ip6-udp": false, "arp-req": true, "non-ip": false,
	},
	"rarp": {
		"ip4-tcp-80": false, "ip4-udp-53": false, "ip4-mcast-udp": false,
		"ip6-tcp-443": false, "ip6-udp": false, "arp-req": false, "non-ip": false,
	},
	"ip6 net 2001:db8::/32": {
		"ip4-tcp-80": false, "ip4-udp-53": false, "ip4-mcast-udp": false,
		"ip6-tcp-443": true, "ip6-udp": true, "arp-req": false, "non-ip": false,
	},
}

func TestEmitEngineMatchesLegacy(t *testing.T) {
	exprs := []string{
		"tcp",
		"udp",
		"ip",
		"ip6",
		"arp",
		"rarp",
		"host 10.0.0.1",
		"src host 10.0.0.1",
		"dst host 192.168.1.5",
		"ip host 10.0.0.1",
		"ip6 host 2001:db8::1",
		"ether host aa:bb:cc:dd:ee:ff",
		"port 80",
		"src port 1234",
		"dst port 9999",
		"tcp port 80",
		"udp port 53",
		"net 10.0.0.0/24",
		"net 192.168.0.0/16",
		"ip6 net 2001:db8::/32",
		"tcp and port 80",
		"tcp or udp",
		"host 10.0.0.1 and udp",
		"(tcp or udp) and host 10.0.0.1",
	}
	pkts := bridgePackets(t)

	for _, expr := range exprs {
		t.Run(expr, func(t *testing.T) {
			e := NewExpression(expr)
			if e == nil {
				t.Fatalf("no expression for %q", expr)
			}
			f := e.Compile()
			if f == nil {
				t.Fatalf("nil filter for %q", expr)
			}
			legacy, err := f.Compile()
			if err != nil {
				t.Fatalf("legacy compile: %v", err)
			}
			modern, err := compileFilter(f.(emitter), ethernetLayout{})
			if err != nil {
				t.Fatalf("label-engine compile: %v", err)
			}
			modernVM, err := bpf.NewVM(modern)
			if err != nil {
				t.Fatalf("label-engine VM: %v", err)
			}

			legacyVM, err := bpf.NewVM(legacy)
			if err != nil {
				// The legacy generator produced an unloadable program.
				// Verify it is a documented defect and check the label
				// engine against hand-derived verdicts instead.
				want, known := legacyBroken[expr]
				if !known {
					t.Fatalf("legacy VM rejected program and %q is not a documented defect: %v", expr, err)
				}
				for name, pkt := range pkts {
					mRet, err := modernVM.Run(pkt)
					if err != nil {
						t.Fatalf("label-engine run %s: %v", name, err)
					}
					if (mRet > 0) != want[name] {
						t.Errorf("label engine verdict on %s: got %v, want %v", name, mRet > 0, want[name])
					}
				}
				return
			}
			if _, known := legacyBroken[expr]; known {
				t.Fatalf("%q listed as a legacy defect but the legacy program loads fine", expr)
			}
			for name, pkt := range pkts {
				lRet, err := legacyVM.Run(pkt)
				if err != nil {
					t.Fatalf("legacy run %s: %v", name, err)
				}
				mRet, err := modernVM.Run(pkt)
				if err != nil {
					t.Fatalf("label-engine run %s: %v", name, err)
				}
				if (lRet > 0) != (mRet > 0) {
					t.Errorf("verdict mismatch on %s: legacy=%d label=%d\nlegacy insns: %v\nlabel insns:  %v",
						name, lRet, mRet, legacy, modern)
				}
			}
		})
	}
}
