package main

import (
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestTCPDumpPrinterCommonPacketSummaries(t *testing.T) {
	ethernet := func(etherType layers.EthernetType) *layers.Ethernet {
		return &layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
			EthernetType: etherType,
		}
	}
	ipv4 := func(protocol layers.IPProtocol) *layers.IPv4 {
		return &layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: protocol,
			SrcIP:    net.IP{192, 0, 2, 1},
			DstIP:    net.IP{192, 0, 2, 2},
		}
	}

	tests := []struct {
		name     string
		packet   gopacket.Packet
		options  tcpdumpOptions
		expected string
	}{
		{
			name: "udp numeric",
			packet: testPacket(t,
				ethernet(layers.EthernetTypeIPv4),
				ipv4(layers.IPProtocolUDP),
				&layers.UDP{SrcPort: 12345, DstPort: 9999},
				gopacket.Payload([]byte("abc")),
			),
			options:  tcpdumpOptions{numeric: 2},
			expected: "12:34:56.123456 IP 192.0.2.1.12345 > 192.0.2.2.9999: UDP, length 3",
		},
		{
			name: "tcp syn numeric",
			packet: testPacket(t,
				ethernet(layers.EthernetTypeIPv4),
				ipv4(layers.IPProtocolTCP),
				&layers.TCP{SrcPort: 12345, DstPort: 443, Seq: 1000, SYN: true, Window: 4096},
			),
			options:  tcpdumpOptions{numeric: 2},
			expected: "12:34:56.123456 IP 192.0.2.1.12345 > 192.0.2.2.443: Flags [S], seq 0, win 4096, length 0",
		},
		{
			name: "icmp echo request",
			packet: testPacket(t,
				ethernet(layers.EthernetTypeIPv4),
				ipv4(layers.IPProtocolICMPv4),
				&layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0), Id: 7, Seq: 9},
			),
			options:  tcpdumpOptions{numeric: 2},
			expected: "12:34:56.123456 IP 192.0.2.1 > 192.0.2.2: ICMP echo request, id 7, seq 9, length 8",
		},
		{
			name: "arp with link header",
			packet: testPacket(t,
				ethernet(layers.EthernetTypeARP),
				&layers.ARP{
					AddrType:          layers.LinkTypeEthernet,
					Protocol:          layers.EthernetTypeIPv4,
					HwAddressSize:     6,
					ProtAddressSize:   4,
					Operation:         layers.ARPRequest,
					SourceHwAddress:   net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
					SourceProtAddress: net.IP{192, 0, 2, 1}.To4(),
					DstHwAddress:      net.HardwareAddr{0, 0, 0, 0, 0, 0},
					DstProtAddress:    net.IP{192, 0, 2, 2}.To4(),
				},
			),
			options: tcpdumpOptions{numeric: 2, linkLayer: true},
			expected: "12:34:56.123456 00:11:22:33:44:55 > 66:77:88:99:aa:bb, " +
				"ethertype ARP (0x0806), length 60: ARP, Request who-has 192.0.2.2 tell 192.0.2.1, length 60",
		},
		{
			name: "vlan with link header",
			packet: testPacket(t,
				ethernet(layers.EthernetTypeDot1Q),
				&layers.Dot1Q{
					Priority:       0,
					VLANIdentifier: 3,
					Type:           layers.EthernetTypeIPv4,
				},
				ipv4(layers.IPProtocolTCP),
				&layers.TCP{SrcPort: 791, DstPort: 52222, FIN: true, ACK: true, Window: 57},
			),
			options: tcpdumpOptions{numeric: 2, linkLayer: true},
			expected: "12:34:56.123456 00:11:22:33:44:55 > 66:77:88:99:aa:bb, " +
				"ethertype 802.1Q (0x8100), length 60: vlan 3, p 0, ethertype IPv4, " +
				"192.0.2.1.791 > 192.0.2.2.52222: Flags [F.], seq 0, ack 0, win 57, length 0",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := newTCPDumpPrinter(test.options).format(test.packet); got != test.expected {
				t.Errorf("format() = %q, want %q", got, test.expected)
			}
		})
	}
}

func TestTCPDumpPrinterNumericLevels(t *testing.T) {
	tests := []struct {
		name    string
		numeric int
		want    string
	}{
		{name: "default", want: "192.0.2.1.https"},
		{name: "-n", numeric: 1, want: "192.0.2.1.https"},
		{name: "-nn", numeric: 2, want: "192.0.2.1.443"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			printer := newTCPDumpPrinter(tcpdumpOptions{numeric: test.numeric})
			if got := printer.endpoint("192.0.2.1", 443, "tcp"); got != test.want {
				t.Errorf("endpoint() = %q, want %q", got, test.want)
			}
		})
	}
}

func testPacket(t *testing.T, serializableLayers ...gopacket.SerializableLayer) gopacket.Packet {
	t.Helper()

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true}
	if err := gopacket.SerializeLayers(buffer, options, serializableLayers...); err != nil {
		t.Fatalf("serialize packet: %v", err)
	}

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	packet.Metadata().CaptureInfo = gopacket.CaptureInfo{
		Timestamp:     time.Date(2026, time.July, 15, 12, 34, 56, 123456000, time.Local),
		CaptureLength: len(buffer.Bytes()),
		Length:        len(buffer.Bytes()),
	}
	return packet
}
