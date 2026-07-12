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
	"testing"

	"golang.org/x/net/bpf"
)

func rawIPv4Protocol(proto byte) []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	pkt[9] = proto
	pkt[12], pkt[13], pkt[14], pkt[15] = 192, 0, 2, 1
	pkt[16], pkt[17], pkt[18], pkt[19] = 198, 51, 100, 1
	return pkt
}

func rawIPv6Protocol(nextHeader byte) []byte {
	pkt := make([]byte, 60)
	pkt[0] = 0x60
	pkt[6] = nextHeader
	pkt[8] = 0x20
	pkt[9] = 0x01
	pkt[24] = 0x20
	pkt[25] = 0x01
	return pkt
}

func ethernetProtocolFrame(etherType uint16, payload []byte) []byte {
	pkt := make([]byte, 14+len(payload))
	binary.BigEndian.PutUint16(pkt[12:14], etherType)
	copy(pkt[14:], payload)
	return pkt
}

func filterVerdict(t *testing.T, expr string, link LinkType, packet []byte) bool {
	t.Helper()
	insns, err := Compile(expr, link)
	if err != nil {
		t.Fatalf("Compile(%q): %v", expr, err)
	}
	vm, err := bpf.NewVM(insns)
	if err != nil {
		t.Fatalf("NewVM(%q): %v", expr, err)
	}
	out, err := vm.Run(packet)
	if err != nil {
		t.Fatalf("Run(%q): %v", expr, err)
	}
	return out != 0
}

func TestProtocolPrimitiveMatrix(t *testing.T) {
	ip4 := rawIPv4Protocol(0)
	ip6 := rawIPv6Protocol(0)
	fragmentUDP := rawIPv6Protocol(byte(ip6ContinuationPacket))
	fragmentUDP[40] = byte(ipProtocolUDP)

	tests := []struct {
		name   string
		expr   string
		packet []byte
		want   bool
	}{
		{"tcp accepts IPv4", "tcp", rawIPv4Protocol(byte(ipProtocolTCP)), true},
		{"tcp accepts IPv6", "tcp", rawIPv6Protocol(byte(ipProtocolTCP)), true},
		{"tcp rejects UDP", "tcp", rawIPv4Protocol(byte(ipProtocolUDP)), false},
		{"udp accepts IPv4", "udp", rawIPv4Protocol(byte(ipProtocolUDP)), true},
		{"udp accepts IPv6", "udp", rawIPv6Protocol(byte(ipProtocolUDP)), true},
		{"udp rejects TCP", "udp", rawIPv4Protocol(byte(ipProtocolTCP)), false},
		{"icmp accepts IPv4 ICMP", "icmp", rawIPv4Protocol(byte(ipProtocolIcmp)), true},
		{"icmp rejects IPv6 ICMP", "icmp", rawIPv6Protocol(byte(ipProtocolIcmp6)), false},
		{"icmp6 accepts IPv6", "icmp6", rawIPv6Protocol(byte(ipProtocolIcmp6)), true},
		{"icmp6 rejects IPv4", "icmp6", rawIPv4Protocol(byte(ipProtocolIcmp)), false},
		{"igmp accepts IPv4", "igmp", rawIPv4Protocol(byte(ipProtocolIgmp)), true},
		{"igmp rejects IPv6", "igmp", rawIPv6Protocol(byte(ipProtocolIgmp)), false},
		{"pim accepts IPv4", "pim", rawIPv4Protocol(byte(ipProtocolPim)), true},
		{"pim accepts IPv6", "pim", rawIPv6Protocol(byte(ipProtocolPim)), true},
		{"esp accepts IPv4", "esp", rawIPv4Protocol(byte(ipProtocolEsp)), true},
		{"esp accepts IPv6", "esp", rawIPv6Protocol(byte(ipProtocolEsp)), true},
		{"ah accepts IPv4", "ah", rawIPv4Protocol(byte(ipProtocolAh)), true},
		{"ah accepts IPv6", "ah", rawIPv6Protocol(byte(ipProtocolAh)), true},
		{"vrrp accepts IPv4", "vrrp", rawIPv4Protocol(byte(ipProtocolVrrp)), true},
		{"vrrp accepts IPv6", "vrrp", rawIPv6Protocol(byte(ipProtocolVrrp)), true},
		{"UDP follows IPv6 continuation header", "udp", fragmentUDP, true},
		{"bare IPv4 rejects IPv6", "ip", ip6, false},
		{"bare IPv4 accepts IPv4", "ip", ip4, true},
		{"bare IPv6 accepts IPv6", "ip6", ip6, true},
		{"bare IPv6 rejects IPv4", "ip6", ip4, false},
	}

	for _, tt := range tests {
		t.Run(tt.name+"/raw", func(t *testing.T) {
			if got := filterVerdict(t, tt.expr, LinkTypeRaw, tt.packet); got != tt.want {
				t.Errorf("RAW verdict=%v, want %v", got, tt.want)
			}
		})
	}

	ethernetCases := []struct {
		name   string
		expr   string
		packet []byte
		want   bool
	}{
		{"ip IPv4", "ip", ethernetProtocolFrame(uint16(etherTypeIPv4), rawIPv4Protocol(byte(ipProtocolTCP))), true},
		{"ip rejects IPv6", "ip", ethernetProtocolFrame(uint16(etherTypeIPv6), rawIPv6Protocol(byte(ipProtocolTCP))), false},
		{"ip6 IPv6", "ip6", ethernetProtocolFrame(uint16(etherTypeIPv6), rawIPv6Protocol(byte(ipProtocolTCP))), true},
		{"ip6 rejects IPv4", "ip6", ethernetProtocolFrame(uint16(etherTypeIPv4), rawIPv4Protocol(byte(ipProtocolTCP))), false},
		{"tcp IPv4", "tcp", ethernetProtocolFrame(uint16(etherTypeIPv4), rawIPv4Protocol(byte(ipProtocolTCP))), true},
		{"tcp IPv6", "tcp", ethernetProtocolFrame(uint16(etherTypeIPv6), rawIPv6Protocol(byte(ipProtocolTCP))), true},
		{"tcp rejects UDP", "tcp", ethernetProtocolFrame(uint16(etherTypeIPv4), rawIPv4Protocol(byte(ipProtocolUDP))), false},
		{"udp IPv4", "udp", ethernetProtocolFrame(uint16(etherTypeIPv4), rawIPv4Protocol(byte(ipProtocolUDP))), true},
		{"udp IPv6", "udp", ethernetProtocolFrame(uint16(etherTypeIPv6), rawIPv6Protocol(byte(ipProtocolUDP))), true},
		{"udp rejects TCP", "udp", ethernetProtocolFrame(uint16(etherTypeIPv4), rawIPv4Protocol(byte(ipProtocolTCP))), false},
		{"arp", "arp", ethernetProtocolFrame(uint16(etherTypeArp), make([]byte, 28)), true},
		{"arp rejects rarp", "arp", ethernetProtocolFrame(uint16(etherTypeRarp), make([]byte, 28)), false},
		{"rarp", "rarp", ethernetProtocolFrame(uint16(etherTypeRarp), make([]byte, 28)), true},
		{"rarp rejects arp", "rarp", ethernetProtocolFrame(uint16(etherTypeArp), make([]byte, 28)), false},
		{"icmp IPv4", "icmp", ethernetProtocolFrame(uint16(etherTypeIPv4), rawIPv4Protocol(byte(ipProtocolIcmp))), true},
		{"icmp rejects IPv6", "icmp", ethernetProtocolFrame(uint16(etherTypeIPv6), rawIPv6Protocol(byte(ipProtocolIcmp6))), false},
		{"icmp6 IPv6", "icmp6", ethernetProtocolFrame(uint16(etherTypeIPv6), rawIPv6Protocol(byte(ipProtocolIcmp6))), true},
		{"icmp6 rejects IPv4", "icmp6", ethernetProtocolFrame(uint16(etherTypeIPv4), rawIPv4Protocol(byte(ipProtocolIcmp))), false},
		{"PIM IPv4", "pim", ethernetProtocolFrame(uint16(etherTypeIPv4), rawIPv4Protocol(byte(ipProtocolPim))), true},
		{"ESP IPv6", "esp", ethernetProtocolFrame(uint16(etherTypeIPv6), rawIPv6Protocol(byte(ipProtocolEsp))), true},
		{"AH IPv4", "ah", ethernetProtocolFrame(uint16(etherTypeIPv4), rawIPv4Protocol(byte(ipProtocolAh))), true},
		{"VRRP IPv6", "vrrp", ethernetProtocolFrame(uint16(etherTypeIPv6), rawIPv6Protocol(byte(ipProtocolVrrp))), true},
	}
	for _, tt := range ethernetCases {
		t.Run(tt.name+"/ethernet", func(t *testing.T) {
			if got := filterVerdict(t, tt.expr, LinkTypeEthernet, tt.packet); got != tt.want {
				t.Errorf("Ethernet verdict=%v, want %v", got, tt.want)
			}
		})
	}
}
