package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// tcpdumpOptions covers the common tcpdump display switches. It deliberately
// keeps capture concerns (such as interface selection) out of the formatter.
type tcpdumpOptions struct {
	numeric   int
	quiet     bool
	verbosity int
	linkLayer bool
	hexDump   bool
	asciiDump bool
}

type tcpdumpPrinter struct {
	options      tcpdumpOptions
	hostNames    map[string]string
	tcpSequences map[tcpFlow]uint32
}

type tcpFlow string

func newTCPDumpPrinter(options tcpdumpOptions) *tcpdumpPrinter {
	return &tcpdumpPrinter{
		options:      options,
		hostNames:    make(map[string]string),
		tcpSequences: make(map[tcpFlow]uint32),
	}
}

func (p *tcpdumpPrinter) format(packet gopacket.Packet) string {
	var output strings.Builder

	timestamp := packet.Metadata().Timestamp
	if timestamp.IsZero() {
		// The syscall capture backend does not expose a kernel timestamp. Keep
		// tcpdump's timestamped line format even on that backend.
		timestamp = time.Now()
	}
	output.WriteString(timestamp.Local().Format("15:04:05.000000"))
	output.WriteByte(' ')

	if ethernetLayer := packet.Layer(layers.LayerTypeEthernet); ethernetLayer != nil && p.options.linkLayer {
		output.WriteString(p.formatEthernet(ethernetLayer.(*layers.Ethernet), packet))
	}

	switch {
	case packet.Layer(layers.LayerTypeIPv4) != nil:
		output.WriteString("IP ")
		output.WriteString(p.formatIPv4(packet, packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)))
	case packet.Layer(layers.LayerTypeIPv6) != nil:
		output.WriteString("IP6 ")
		output.WriteString(p.formatIPv6(packet, packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)))
	case packet.Layer(layers.LayerTypeARP) != nil:
		output.WriteString(p.formatARP(packet.Layer(layers.LayerTypeARP).(*layers.ARP), packet))
	default:
		output.WriteString(p.formatUnknown(packet))
	}

	if p.options.hexDump || p.options.asciiDump {
		output.WriteString(p.formatDump(packet.Data()))
	}
	return output.String()
}

func (p *tcpdumpPrinter) formatEthernet(ethernet *layers.Ethernet, packet gopacket.Packet) string {
	return fmt.Sprintf(
		"%s > %s, ethertype %s (0x%04x), length %d: ",
		ethernet.SrcMAC,
		ethernet.DstMAC,
		etherTypeName(ethernet.EthernetType),
		uint16(ethernet.EthernetType),
		packetLength(packet),
	)
}

func (p *tcpdumpPrinter) formatIPv4(packet gopacket.Packet, ip *layers.IPv4) string {
	source := p.host(ip.SrcIP)
	destination := p.host(ip.DstIP)
	prefix := p.ipv4VerbosePrefix(ip)

	if p.options.quiet {
		return prefix + fmt.Sprintf("%s > %s: %s %d", source, destination, ip.Protocol, len(ip.Payload))
	}
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		return prefix + fmt.Sprintf("%s > %s: %s", source, destination, p.formatICMPv4(icmpLayer.(*layers.ICMPv4)))
	}

	switch transport := packet.TransportLayer().(type) {
	case *layers.TCP:
		return prefix + p.formatTCP(source, destination, transport)
	case *layers.UDP:
		return prefix + p.formatUDP(packet, source, destination, transport)
	default:
		return prefix + fmt.Sprintf("%s > %s: %s, length %d", source, destination, ip.Protocol, len(ip.Payload))
	}
}

func (p *tcpdumpPrinter) formatIPv6(packet gopacket.Packet, ip *layers.IPv6) string {
	source := p.host(ip.SrcIP)
	destination := p.host(ip.DstIP)
	prefix := p.ipv6VerbosePrefix(ip)

	if p.options.quiet {
		return prefix + fmt.Sprintf("%s > %s: %s %d", source, destination, ip.NextHeader, len(ip.Payload))
	}
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv6); icmpLayer != nil {
		return prefix + fmt.Sprintf("%s > %s: %s", source, destination, p.formatICMPv6(packet, icmpLayer.(*layers.ICMPv6)))
	}

	switch transport := packet.TransportLayer().(type) {
	case *layers.TCP:
		return prefix + p.formatTCP(source, destination, transport)
	case *layers.UDP:
		return prefix + p.formatUDP(packet, source, destination, transport)
	default:
		return prefix + fmt.Sprintf("%s > %s: %s, length %d", source, destination, ip.NextHeader, len(ip.Payload))
	}
}

func (p *tcpdumpPrinter) ipv4VerbosePrefix(ip *layers.IPv4) string {
	if p.options.verbosity == 0 {
		return ""
	}

	flags := "none"
	if value := ip.Flags.String(); value != "" {
		flags = value
	}
	return fmt.Sprintf(
		"(tos 0x%02x, ttl %d, id %d, offset %d, flags [%s], proto %s (%d), length %d) ",
		ip.TOS,
		ip.TTL,
		ip.Id,
		ip.FragOffset,
		flags,
		ip.Protocol,
		uint8(ip.Protocol),
		ip.Length,
	)
}

func (p *tcpdumpPrinter) ipv6VerbosePrefix(ip *layers.IPv6) string {
	if p.options.verbosity == 0 {
		return ""
	}
	return fmt.Sprintf(
		"(flowlabel 0x%05x, hlim %d, next-header %s (%d), payload length %d) ",
		ip.FlowLabel,
		ip.HopLimit,
		ip.NextHeader,
		uint8(ip.NextHeader),
		ip.Length,
	)
}

func (p *tcpdumpPrinter) formatTCP(source, destination string, tcp *layers.TCP) string {
	sourceEndpoint := p.endpoint(source, uint16(tcp.SrcPort), "tcp")
	destinationEndpoint := p.endpoint(destination, uint16(tcp.DstPort), "tcp")
	payloadLength := len(tcp.Payload)

	if p.options.quiet {
		return fmt.Sprintf("%s > %s: tcp %d", sourceEndpoint, destinationEndpoint, payloadLength)
	}

	flow := newTCPFlow(sourceEndpoint, destinationEndpoint)
	sequence := p.relativeSequence(flow, tcp.Seq)

	fields := []string{fmt.Sprintf("Flags [%s]", tcpFlags(tcp))}
	if payloadLength > 0 {
		fields = append(fields, fmt.Sprintf("seq %d:%d", sequence, sequence+uint32(payloadLength)))
	} else if tcp.SYN || tcp.FIN {
		fields = append(fields, fmt.Sprintf("seq %d", sequence))
	}
	if tcp.ACK {
		acknowledgement := p.relativeSequence(newTCPFlow(destinationEndpoint, sourceEndpoint), tcp.Ack)
		fields = append(fields, fmt.Sprintf("ack %d", acknowledgement))
	}
	fields = append(fields, fmt.Sprintf("win %d", tcp.Window))
	if options := tcpOptions(tcp.Options); options != "" {
		fields = append(fields, "options ["+options+"]")
	}
	if p.options.verbosity > 0 {
		fields = append(fields, fmt.Sprintf("length %d", payloadLength), fmt.Sprintf("cksum 0x%04x", tcp.Checksum))
	} else {
		fields = append(fields, fmt.Sprintf("length %d", payloadLength))
	}

	return fmt.Sprintf("%s > %s: %s", sourceEndpoint, destinationEndpoint, strings.Join(fields, ", "))
}

func newTCPFlow(source, destination string) tcpFlow {
	return tcpFlow(source + "\x00" + destination)
}

func (p *tcpdumpPrinter) relativeSequence(flow tcpFlow, sequence uint32) uint32 {
	base, found := p.tcpSequences[flow]
	if !found {
		p.tcpSequences[flow] = sequence
		return 0
	}
	return sequence - base
}

func (p *tcpdumpPrinter) formatUDP(packet gopacket.Packet, source, destination string, udp *layers.UDP) string {
	sourceEndpoint := p.endpoint(source, uint16(udp.SrcPort), "udp")
	destinationEndpoint := p.endpoint(destination, uint16(udp.DstPort), "udp")
	if p.options.quiet {
		return fmt.Sprintf("%s > %s: udp %d", sourceEndpoint, destinationEndpoint, len(udp.Payload))
	}
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		return fmt.Sprintf("%s > %s: %s", sourceEndpoint, destinationEndpoint, formatDNS(dnsLayer.(*layers.DNS)))
	}
	return fmt.Sprintf("%s > %s: UDP, length %d", sourceEndpoint, destinationEndpoint, len(udp.Payload))
}

func formatDNS(dns *layers.DNS) string {
	// layers.DNS stores the complete DNS message in Contents and deliberately
	// reports no further application payload.
	payloadLength := len(dns.Contents)
	if !dns.QR {
		if len(dns.Questions) == 0 {
			return fmt.Sprintf("%d+ [|domain]", dns.ID)
		}
		question := dns.Questions[0]
		return fmt.Sprintf("%d+ %s? %s. (%d)", dns.ID, question.Type, question.Name, payloadLength)
	}
	return fmt.Sprintf(
		"%d %d/%d/%d (%d)",
		dns.ID,
		len(dns.Answers),
		len(dns.Authorities),
		len(dns.Additionals),
		payloadLength,
	)
}

func (p *tcpdumpPrinter) formatICMPv4(icmp *layers.ICMPv4) string {
	length := len(icmp.Contents) + len(icmp.Payload)
	switch icmp.TypeCode.Type() {
	case layers.ICMPv4TypeEchoRequest:
		return fmt.Sprintf("ICMP echo request, id %d, seq %d, length %d", icmp.Id, icmp.Seq, length)
	case layers.ICMPv4TypeEchoReply:
		return fmt.Sprintf("ICMP echo reply, id %d, seq %d, length %d", icmp.Id, icmp.Seq, length)
	default:
		return fmt.Sprintf("ICMP type %d, code %d, length %d", icmp.TypeCode.Type(), icmp.TypeCode.Code(), length)
	}
}

func (p *tcpdumpPrinter) formatICMPv6(packet gopacket.Packet, icmp *layers.ICMPv6) string {
	length := len(icmp.Contents) + len(icmp.Payload)
	if echoLayer := packet.Layer(layers.LayerTypeICMPv6Echo); echoLayer != nil {
		echo := echoLayer.(*layers.ICMPv6Echo)
		switch icmp.TypeCode.Type() {
		case layers.ICMPv6TypeEchoRequest:
			return fmt.Sprintf("ICMP6, echo request, id %d, seq %d, length %d", echo.Identifier, echo.SeqNumber, length)
		case layers.ICMPv6TypeEchoReply:
			return fmt.Sprintf("ICMP6, echo reply, id %d, seq %d, length %d", echo.Identifier, echo.SeqNumber, length)
		}
	}
	return fmt.Sprintf("ICMP6, type %d, code %d, length %d", icmp.TypeCode.Type(), icmp.TypeCode.Code(), length)
}

func (p *tcpdumpPrinter) formatARP(arp *layers.ARP, packet gopacket.Packet) string {
	source := net.IP(arp.SourceProtAddress).String()
	destination := net.IP(arp.DstProtAddress).String()
	length := packetLength(packet)
	switch arp.Operation {
	case layers.ARPRequest:
		return fmt.Sprintf("ARP, Request who-has %s tell %s, length %d", destination, source, length)
	case layers.ARPReply:
		return fmt.Sprintf("ARP, Reply %s is-at %s, length %d", source, net.HardwareAddr(arp.SourceHwAddress), length)
	default:
		return fmt.Sprintf("ARP, operation %d, length %d", arp.Operation, length)
	}
}

func (p *tcpdumpPrinter) formatUnknown(packet gopacket.Packet) string {
	if ethernetLayer := packet.Layer(layers.LayerTypeEthernet); ethernetLayer != nil {
		ethernet := ethernetLayer.(*layers.Ethernet)
		return fmt.Sprintf(
			"ethertype %s (0x%04x), length %d",
			etherTypeName(ethernet.EthernetType),
			uint16(ethernet.EthernetType),
			packetLength(packet),
		)
	}
	return fmt.Sprintf("unknown link-layer packet, length %d", packetLength(packet))
}

func (p *tcpdumpPrinter) host(ip net.IP) string {
	address := ip.String()
	if p.options.numeric > 0 {
		return address
	}
	if name, found := p.hostNames[address]; found {
		return name
	}

	name := address
	if names, err := net.LookupAddr(address); err == nil && len(names) > 0 {
		name = strings.TrimSuffix(names[0], ".")
	}
	p.hostNames[address] = name
	return name
}

func (p *tcpdumpPrinter) endpoint(host string, port uint16, protocol string) string {
	return host + "." + serviceName(port, protocol, p.options.numeric >= 2)
}

func serviceName(port uint16, protocol string, numeric bool) string {
	if numeric {
		return strconv.Itoa(int(port))
	}

	if name, found := commonServices[protocol][port]; found {
		return name
	}
	return strconv.Itoa(int(port))
}

var commonServices = map[string]map[uint16]string{
	"tcp": {
		22:  "ssh",
		23:  "telnet",
		25:  "smtp",
		53:  "domain",
		80:  "http",
		110: "pop3",
		143: "imap",
		443: "https",
		587: "submission",
	},
	"udp": {
		53: "domain", 67: "bootps", 68: "bootpc", 69: "tftp", 123: "ntp", 161: "snmp", 162: "snmptrap", 5353: "mdns",
	},
}

func tcpFlags(tcp *layers.TCP) string {
	var flags strings.Builder
	if tcp.FIN {
		flags.WriteByte('F')
	}
	if tcp.SYN {
		flags.WriteByte('S')
	}
	if tcp.RST {
		flags.WriteByte('R')
	}
	if tcp.PSH {
		flags.WriteByte('P')
	}
	if tcp.ACK {
		flags.WriteByte('.')
	}
	if tcp.URG {
		flags.WriteByte('U')
	}
	if tcp.ECE {
		flags.WriteByte('E')
	}
	if tcp.CWR {
		flags.WriteByte('W')
	}
	if tcp.NS {
		flags.WriteByte('N')
	}
	return flags.String()
}

func tcpOptions(options []layers.TCPOption) string {
	values := make([]string, 0, len(options))
	for _, option := range options {
		switch option.OptionType {
		case layers.TCPOptionKindEndList:
			values = append(values, "eol")
		case layers.TCPOptionKindNop:
			values = append(values, "nop")
		case layers.TCPOptionKindMSS:
			if len(option.OptionData) >= 2 {
				values = append(values, fmt.Sprintf("mss %d", binary.BigEndian.Uint16(option.OptionData)))
			}
		case layers.TCPOptionKindWindowScale:
			if len(option.OptionData) >= 1 {
				values = append(values, fmt.Sprintf("wscale %d", option.OptionData[0]))
			}
		case layers.TCPOptionKindSACKPermitted:
			values = append(values, "sackOK")
		case layers.TCPOptionKindTimestamps:
			if len(option.OptionData) >= 8 {
				timestampValue := binary.BigEndian.Uint32(option.OptionData[:4])
				echoReplyValue := binary.BigEndian.Uint32(option.OptionData[4:8])
				values = append(values, fmt.Sprintf("TS val %d ecr %d", timestampValue, echoReplyValue))
			}
		default:
			values = append(values, fmt.Sprintf("unknown-%d", option.OptionType))
		}
	}
	return strings.Join(values, ",")
}

func (p *tcpdumpPrinter) formatDump(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	var output strings.Builder
	for offset := 0; offset < len(data); offset += 16 {
		end := offset + 16
		if end > len(data) {
			end = len(data)
		}
		line := data[offset:end]

		output.WriteString("\n\t")
		if p.options.hexDump {
			output.WriteString(fmt.Sprintf("0x%04x:  ", offset))
			for index := 0; index < 16; index++ {
				if index < len(line) {
					output.WriteString(fmt.Sprintf("%02x", line[index]))
				} else {
					output.WriteString("  ")
				}
				output.WriteByte(' ')
			}
		}
		if p.options.asciiDump || p.options.hexDump {
			for _, value := range line {
				character := rune(value)
				if unicode.IsPrint(character) {
					output.WriteRune(character)
				} else {
					output.WriteByte('.')
				}
			}
		}
	}
	return output.String()
}

func packetLength(packet gopacket.Packet) int {
	if length := packet.Metadata().Length; length > 0 {
		return length
	}
	return len(packet.Data())
}

func etherTypeName(etherType layers.EthernetType) string {
	switch etherType {
	case layers.EthernetTypeIPv4:
		return "IPv4"
	case layers.EthernetTypeIPv6:
		return "IPv6"
	case layers.EthernetTypeARP:
		return "ARP"
	case layers.EthernetTypeDot1Q:
		return "802.1Q"
	default:
		return etherType.String()
	}
}
