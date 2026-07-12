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
	"bytes"
	"context"
	"fmt"
	"net"
	"strconv"

	"golang.org/x/net/bpf"
)

var resolver net.Resolver

// primitive implements Filter and Element
type primitive struct {
	kind        filterKind
	direction   filterDirection
	protocol    filterProtocol
	subProtocol filterSubProtocol
	negator     bool
	id          string
}

func (p primitive) IsPrimitive() bool { return true }
func (p primitive) Type() ElementType { return Primitive }
func (p primitive) Distill() Filter   { return p }

func (p primitive) Combine(o *primitive) *primitive {
	if p.kind == filterKindMulticast || o.kind == filterKindMulticast {
		return nil
	}
	if p.Equal(o) {
		return &p
	}
	c := primitive{}
	switch {
	case p.kind == o.kind || o.kind == filterKindUnset:
		c.kind = p.kind
	case p.kind == filterKindUnset:
		c.kind = o.kind
	default:
		return nil
	}
	switch {
	case p.direction == o.direction || o.direction == filterDirectionUnset:
		c.direction = p.direction
	case p.direction == filterDirectionUnset:
		c.direction = o.direction
	default:
		return nil
	}
	switch {
	case p.protocol == o.protocol || o.protocol == filterProtocolUnset:
		c.protocol = p.protocol
	case p.protocol == filterProtocolUnset:
		c.protocol = o.protocol
	default:
		return nil
	}
	switch {
	case p.subProtocol == o.subProtocol || o.subProtocol == filterSubProtocolUnset:
		c.subProtocol = p.subProtocol
	case p.subProtocol == filterSubProtocolUnset:
		c.subProtocol = o.subProtocol
	default:
		return nil
	}
	switch {
	case p.id == o.id || o.id == "":
		c.id = p.id
	case p.id == "":
		c.id = o.id
	default:
		return nil
	}
	switch p.negator {
	case o.negator:
		c.negator = p.negator
	default:
		return nil
	}
	return &c
}

// Compile validates the primitive and delegates to the two-pass assembler.
func (p primitive) Compile(layout linkLayout) ([]bpf.Instruction, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	return compileFilter(p, layout)
}

// Size compiles and returns the instruction count. Guarantees len(Compile) == Size.
func (p primitive) Size(layout linkLayout) uint8 {
	if p.isAlwaysReject(layout) {
		return 2
	}
	if p.isAlwaysAccept(layout) {
		return 2
	}
	insns, err := p.Compile(layout)
	if err != nil || len(insns) == 0 {
		return 2
	}
	return uint8(len(insns))
}

// isAlwaysReject returns true for L2-only primitives on non-L2 link types.
func (p primitive) isAlwaysReject(layout linkLayout) bool {
	if layout.hasL2Protocols() {
		return false
	}
	switch p.kind {
	case filterKindHost:
		switch p.protocol {
		case filterProtocolEther, filterProtocolArp, filterProtocolRarp:
			return true
		}
	case filterKindNet:
		switch p.protocol {
		case filterProtocolArp, filterProtocolRarp:
			return true
		}
	case filterKindMulticast:
		switch p.protocol {
		case filterProtocolUnset, filterProtocolEther:
			return true
		}
	case filterKindUnset:
		switch p.protocol {
		case filterProtocolArp, filterProtocolRarp:
			return true
		}
	}
	return false
}

// isAlwaysAccept always returns false.
func (p primitive) isAlwaysAccept(layout linkLayout) bool { return false }

// emit generates instructions for this primitive, branching to onMatch when
// the filter matches and onMiss when it does not. Negation is handled
// externally by the negated wrapper which swaps onMatch/onMiss before calling emit.
func (p primitive) emit(b *prog, onMatch, onMiss labelID) {
	switch p.kind {
	case filterKindHost:
		p.emitHost(b, onMatch, onMiss)
	case filterKindPort:
		p.emitPort(b, onMatch, onMiss)
	case filterKindNet:
		p.emitNet(b, onMatch, onMiss)
	case filterKindMulticast:
		p.emitMulticast(b, onMatch, onMiss)
	case filterKindUnset:
		p.emitUnset(b, onMatch, onMiss)
	}
}

func (p primitive) emitHost(b *prog, onMatch, onMiss labelID) {
	switch p.protocol {
	case filterProtocolEther:
		if !b.layout.hasL2Protocols() {
			b.emitJump(onMiss)
			return
		}
		// No loadEtherKind: ether address check is independent of ethertype.
		b.checkEtherAddresses(p.direction, p.id, onMatch, onMiss)

	case filterProtocolIP6:
		b.loadEtherKind()
		ip6Ok := b.newLabel()
		b.compareProtocolIP6(ip6Ok, onMiss)
		b.bind(ip6Ok)
		_, a6, _ := p.getAddrs()
		b.checkIP6HostAddresses(p.direction, a6[0], onMatch, onMiss)

	case filterProtocolIP:
		b.loadEtherKind()
		ip4Ok := b.newLabel()
		b.compareProtocolIP4(ip4Ok, onMiss)
		b.bind(ip4Ok)
		a4, _, _ := p.getAddrs()
		b.checkIP4HostAddresses(p.direction, a4[0], onMatch, onMiss)

	case filterProtocolArp:
		if !b.layout.hasL2Protocols() {
			b.emitJump(onMiss)
			return
		}
		b.loadEtherKind()
		arpOk := b.newLabel()
		b.compareProtocolArp(arpOk, onMiss)
		b.bind(arpOk)
		a4, _, _ := p.getAddrs()
		b.checkIP4ArpAddresses(p.direction, a4[0], onMatch, onMiss)

	case filterProtocolRarp:
		if !b.layout.hasL2Protocols() {
			b.emitJump(onMiss)
			return
		}
		b.loadEtherKind()
		rarpOk := b.newLabel()
		b.compareProtocolRarp(rarpOk, onMiss)
		b.bind(rarpOk)
		a4, _, _ := p.getAddrs()
		b.checkIP4ArpAddresses(p.direction, a4[0], onMatch, onMiss)

	case filterProtocolUnset:
		p.emitHostUnset(b, onMatch, onMiss)
	}
}

func (p primitive) emitHostUnset(b *prog, onMatch, onMiss labelID) {
	a4, a6, _ := p.getAddrs()
	b.loadEtherKind()
	hasL2 := b.layout.hasL2Protocols()

	if len(a4) > 0 {
		ip4Ok := b.newLabel()
		// Determine where the IPv4 protocol-miss branch goes.
		// With L2: always to afterIP4 (to check ARP/RARP).
		// Without L2: directly to onMiss (no ARP/RARP on non-L2 links).
		if hasL2 {
			afterIP4 := b.newLabel()
			b.compareProtocolIP4(ip4Ok, afterIP4)
			b.bind(ip4Ok)
			b.checkIP4HostAddresses(p.direction, a4[0], onMatch, onMiss)
			b.bind(afterIP4)
			// ARP and RARP share the same address-check label.
			arpRarpCheck := b.newLabel()
			notARP := b.newLabel()
			b.compareProtocolArp(arpRarpCheck, notARP)
			b.bind(notARP)
			rarpMiss := onMiss
			if len(a6) > 0 {
				rarpMiss = b.newLabel()
			}
			b.compareProtocolRarp(arpRarpCheck, rarpMiss)
			b.bind(arpRarpCheck)
			b.checkIP4ArpAddresses(p.direction, a4[0], onMatch, onMiss)
			if len(a6) > 0 {
				b.bind(rarpMiss)
			}
		} else {
			b.compareProtocolIP4(ip4Ok, onMiss)
			b.bind(ip4Ok)
			b.checkIP4HostAddresses(p.direction, a4[0], onMatch, onMiss)
		}
	}

	if len(a6) > 0 {
		ip6Ok := b.newLabel()
		b.compareProtocolIP6(ip6Ok, onMiss)
		b.bind(ip6Ok)
		b.checkIP6HostAddresses(p.direction, a6[0], onMatch, onMiss)
	}
}

func (p primitive) emitPort(b *prog, onMatch, onMiss labelID) {
	portInt, err := findPort(p.id)
	if err != nil {
		b.emitJump(onMiss)
		return
	}
	port := uint32(portInt)
	b.loadEtherKind()

	switch p.protocol {
	case filterProtocolIP6:
		ip6Ok := b.newLabel()
		b.compareProtocolIP6(ip6Ok, onMiss)
		b.bind(ip6Ok)
		b.emit(loadIPv6Protocol(b.layout))
		p.emitSubProtocolCompare(b, onMatch, onMiss, true)
		b.checkPorts(p.direction, port, onMatch, onMiss, true)

	case filterProtocolIP:
		ip4Ok := b.newLabel()
		b.compareProtocolIP4(ip4Ok, onMiss)
		b.bind(ip4Ok)
		b.emit(loadIPv4Protocol(b.layout))
		p.emitSubProtocolCompare(b, onMatch, onMiss, false)
		b.checkPorts(p.direction, port, onMatch, onMiss, false)

	case filterProtocolUnset:
		// Dual-stack: try IPv6 first, then IPv4.
		tryIP4 := b.newLabel()
		ip6Ok := b.newLabel()
		b.compareProtocolIP6(ip6Ok, tryIP4)
		b.bind(ip6Ok)
		b.emit(loadIPv6Protocol(b.layout))
		p.emitSubProtocolCompare(b, onMatch, onMiss, true)
		b.checkPorts(p.direction, port, onMatch, onMiss, true)

		b.bind(tryIP4)
		ip4Ok := b.newLabel()
		b.compareProtocolIP4(ip4Ok, onMiss)
		b.bind(ip4Ok)
		b.emit(loadIPv4Protocol(b.layout))
		p.emitSubProtocolCompare(b, onMatch, onMiss, false)
		b.checkPorts(p.direction, port, onMatch, onMiss, false)
	}
}

func (p primitive) emitNet(b *prog, onMatch, onMiss labelID) {
	switch p.protocol {
	case filterProtocolIP6:
		b.loadEtherKind()
		ip6Ok := b.newLabel()
		b.compareProtocolIP6(ip6Ok, onMiss)
		b.bind(ip6Ok)
		addr, network, _ := getNetAndMask(p.id)
		b.checkIP6NetAddresses(p.direction, addr, network.Mask, onMatch, onMiss)

	case filterProtocolIP:
		b.loadEtherKind()
		ip4Ok := b.newLabel()
		b.compareProtocolIP4(ip4Ok, onMiss)
		b.bind(ip4Ok)
		b.checkIP4NetHostAddresses(p.direction, p.id, onMatch, onMiss)

	case filterProtocolArp:
		if !b.layout.hasL2Protocols() {
			b.emitJump(onMiss)
			return
		}
		b.loadEtherKind()
		arpOk := b.newLabel()
		b.compareProtocolArp(arpOk, onMiss)
		b.bind(arpOk)
		b.checkIP4NetArpAddresses(p.direction, p.id, onMatch, onMiss)

	case filterProtocolRarp:
		if !b.layout.hasL2Protocols() {
			b.emitJump(onMiss)
			return
		}
		b.loadEtherKind()
		rarpOk := b.newLabel()
		b.compareProtocolRarp(rarpOk, onMiss)
		b.bind(rarpOk)
		b.checkIP4NetArpAddresses(p.direction, p.id, onMatch, onMiss)

	case filterProtocolUnset:
		p.emitNetUnset(b, onMatch, onMiss)
	}
}

func (p primitive) emitNetUnset(b *prog, onMatch, onMiss labelID) {
	b.loadEtherKind()
	addr, network, _ := getNetAndMask(p.id)
	hasL2 := b.layout.hasL2Protocols()

	if addr.To4() != nil {
		ip4Ok := b.newLabel()
		var arpStart labelID

		if hasL2 {
			arpStart = b.newLabel()
			b.compareProtocolIP4(ip4Ok, arpStart)
		} else {
			b.compareProtocolIP4(ip4Ok, onMiss)
		}
		b.bind(ip4Ok)
		b.checkIP4NetHostAddresses(p.direction, p.id, onMatch, onMiss)

		if hasL2 {
			b.bind(arpStart)
			arpOk := b.newLabel()
			tryRARP := b.newLabel()
			b.compareProtocolArp(arpOk, tryRARP)
			b.bind(arpOk)

			arpAddrDo := b.newLabel()
			b.emitJump(arpAddrDo)

			b.bind(tryRARP)
			rarpOk := b.newLabel()
			b.compareProtocolRarp(rarpOk, onMiss)
			b.bind(rarpOk)

			b.bind(arpAddrDo)
			b.checkIP4NetArpAddresses(p.direction, p.id, onMatch, onMiss)
		}
	} else {
		ip6Ok := b.newLabel()
		b.compareProtocolIP6(ip6Ok, onMiss)
		b.bind(ip6Ok)
		b.checkIP6NetAddresses(p.direction, addr, network.Mask, onMatch, onMiss)
	}
}

func (p primitive) emitMulticast(b *prog, onMatch, onMiss labelID) {
	switch p.protocol {
	case filterProtocolUnset, filterProtocolEther:
		if !b.layout.hasL2Protocols() {
			b.emitJump(onMiss)
			return
		}
		b.genEtherMulticast(onMatch, onMiss)

	case filterProtocolIP:
		b.loadEtherKind()
		ip4Ok := b.newLabel()
		b.compareProtocolIP4(ip4Ok, onMiss)
		b.bind(ip4Ok)
		b.genIPv4Multicast(onMatch, onMiss)

	case filterProtocolIP6:
		b.loadEtherKind()
		ip6Ok := b.newLabel()
		b.compareProtocolIP6(ip6Ok, onMiss)
		b.bind(ip6Ok)
		b.genIPv6Multicast(onMatch, onMiss)
	}
}

func (p primitive) emitUnset(b *prog, onMatch, onMiss labelID) {
	b.loadEtherKind()

	switch p.protocol {
	case filterProtocolIP:
		// Bare `ip` matches any IPv4 packet by EtherType alone, like tcpdump.
		// Only narrow by protocol number when a sub-protocol was given,
		// e.g. `ip proto tcp`.
		if p.subProtocol == filterSubProtocolUnset {
			b.compareProtocolIP4(onMatch, onMiss)
			return
		}
		ip4Ok := b.newLabel()
		b.compareProtocolIP4(ip4Ok, onMiss)
		b.bind(ip4Ok)
		b.compareIPv4Protocol(p.protoNum(), onMatch, onMiss)

	case filterProtocolIP6:
		// Bare `ip6` matches any IPv6 packet by EtherType alone, like tcpdump.
		// Only narrow by next-header when a sub-protocol was given,
		// e.g. `ip6 proto udp`.
		if p.subProtocol == filterSubProtocolUnset {
			b.compareProtocolIP6(onMatch, onMiss)
			return
		}
		ip6Ok := b.newLabel()
		b.compareProtocolIP6(ip6Ok, onMiss)
		b.bind(ip6Ok)
		p.emitIPv6SubProtocol(b, onMatch, onMiss)

	case filterProtocolArp:
		if !b.layout.hasL2Protocols() {
			b.emitJump(onMiss)
			return
		}
		arpOk := b.newLabel()
		b.compareProtocolArp(arpOk, onMiss)
		b.bind(arpOk)
		b.emitJump(onMatch)

	case filterProtocolRarp:
		if !b.layout.hasL2Protocols() {
			b.emitJump(onMiss)
			return
		}
		rarpOk := b.newLabel()
		b.compareProtocolRarp(rarpOk, onMiss)
		b.bind(rarpOk)
		b.emitJump(onMatch)

	case filterProtocolEther:
		switch p.subProtocol {
		case filterSubProtocolIP:
			b.compareProtocolIP4(onMatch, onMiss)
		case filterSubProtocolIP6:
			b.compareProtocolIP6(onMatch, onMiss)
		case filterSubProtocolArp:
			b.compareProtocolArp(onMatch, onMiss)
		case filterSubProtocolRarp:
			b.compareProtocolRarp(onMatch, onMiss)
		}

	case filterProtocolUnset:
		p.emitUnsetProtocol(b, onMatch, onMiss)
	}
}

// emitIPv6SubProtocol checks for a sub-protocol in an IPv6 packet.
func (p primitive) emitIPv6SubProtocol(b *prog, onMatch, onMiss labelID) {
	switch p.subProtocol {
	case filterSubProtocolStp:
		subOk := b.newLabel()
		b.compareSubProtocolSctp(subOk, onMiss)
		b.bind(subOk)
		b.emitJump(onMatch)
	default:
		b.compareIPv6Protocol(p.protoNum(), onMatch, onMiss)
	}
}

// emitUnsetProtocol emits the dual-stack sub-protocol checks for
// filterProtocolUnset with filterKindUnset.
func (p primitive) emitUnsetProtocol(b *prog, onMatch, onMiss labelID) {
	switch p.subProtocol {
	// IPv4-only sub-protocols.
	case filterSubProtocolIcmp, filterSubProtocolIgmp:
		ip4Ok := b.newLabel()
		b.compareProtocolIP4(ip4Ok, onMiss)
		b.bind(ip4Ok)
		b.compareIPv4Protocol(p.protoNum(), onMatch, onMiss)

	// IPv6-only sub-protocols.
	case filterSubProtocolIcmp6:
		ip6Ok := b.newLabel()
		b.compareProtocolIP6(ip6Ok, onMiss)
		b.bind(ip6Ok)
		b.compareIPv6Protocol(p.protoNum(), onMatch, onMiss)

	// Dual-stack sub-protocols: try IPv6 first, then IPv4.
	case filterSubProtocolUDP, filterSubProtocolTCP, filterSubProtocolStp,
		filterSubProtocolPim, filterSubProtocolEsp, filterSubProtocolAh,
		filterSubProtocolVrrp:
		tryIP4 := b.newLabel()
		ip6Ok := b.newLabel()
		b.compareProtocolIP6(ip6Ok, tryIP4)
		b.bind(ip6Ok)
		p.emitIPv6SubProtocol(b, onMatch, onMiss)

		b.bind(tryIP4)
		ip4Ok := b.newLabel()
		b.compareProtocolIP4(ip4Ok, onMiss)
		b.bind(ip4Ok)
		b.compareIPv4Protocol(p.protoNum(), onMatch, onMiss)
	}
}

// emitSubProtocolCompare emits the sub-protocol comparison for Port primitives.
// On match it falls through to the port check that follows. On miss it branches
// to onMiss. This is shared by the IPv4 and IPv6 port paths.
func (p primitive) emitSubProtocolCompare(b *prog, onMatch, onMiss labelID, ip6 bool) {
	switch p.subProtocol {
	case filterSubProtocolTCP:
		subOk := b.newLabel()
		b.compareSubProtocolTCP(subOk, onMiss)
		b.bind(subOk)

	case filterSubProtocolUDP:
		subOk := b.newLabel()
		b.compareSubProtocolUDP(subOk, onMiss)
		b.bind(subOk)

	case filterSubProtocolStp:
		subOk := b.newLabel()
		b.compareSubProtocolSctp(subOk, onMiss)
		b.bind(subOk)

	case filterSubProtocolUnset:
		// Check SCTP then TCP then UDP. Fall through on any match.
		afterAll := b.newLabel()

		sctpOk := b.newLabel()
		tryTCP := b.newLabel()
		b.compareSubProtocolSctp(sctpOk, tryTCP)
		b.bind(sctpOk)
		b.emitJump(afterAll)

		b.bind(tryTCP)
		tcpOk := b.newLabel()
		tryUDP := b.newLabel()
		b.compareSubProtocolTCP(tcpOk, tryUDP)
		b.bind(tcpOk)
		b.emitJump(afterAll)

		b.bind(tryUDP)
		udpOk := b.newLabel()
		b.compareSubProtocolUDP(udpOk, onMiss)
		b.bind(udpOk)

		b.bind(afterAll)
	}
}

// protoNum maps the primitive's subProtocol to its IP protocol number.
func (p primitive) protoNum() uint32 {
	switch p.subProtocol {
	case filterSubProtocolTCP:
		return ipProtocolTCP
	case filterSubProtocolUDP:
		return ipProtocolUDP
	case filterSubProtocolStp:
		return ipProtocolSctp
	case filterSubProtocolIcmp:
		return ipProtocolIcmp
	case filterSubProtocolIgmp:
		return ipProtocolIgmp
	case filterSubProtocolIcmp6:
		return ipProtocolIcmp6
	case filterSubProtocolPim:
		return ipProtocolPim
	case filterSubProtocolEsp:
		return ipProtocolEsp
	case filterSubProtocolAh:
		return ipProtocolAh
	case filterSubProtocolVrrp:
		return ipProtocolVrrp
	}
	return 0
}

func (p primitive) Equal(f Filter) bool {
	if f == nil {
		return false
	}
	o, ok := f.(primitive)
	if !ok {
		return false
	}
	return p.kind == o.kind &&
		p.direction == o.direction &&
		p.protocol == o.protocol &&
		p.subProtocol == o.subProtocol &&
		p.negator == o.negator &&
		p.id == o.id
}

func (p primitive) validate() error {
	switch {
	case p.subProtocol == filterSubProtocolUnknown:
		return fmt.Errorf("unknown protocol %s", p.id)
	case p.kind == filterKindHost:
		switch p.protocol {
		case filterProtocolIP, filterProtocolIP6, filterProtocolArp, filterProtocolRarp, filterProtocolUnset:
			if p.id == "" {
				return fmt.Errorf("blank host")
			}
			addr, network, _ := getNetAndMask(p.id)
			var maskFull net.IPMask
			if addr != nil && network != nil {
				if addr.To4() != nil {
					maskFull = ip4MaskFull
				} else {
					maskFull = ip6MaskFull
				}
				if !bytes.Equal(network.Mask, maskFull) {
					return fmt.Errorf("invalid host address with CIDR: %s", p.id)
				}
			}
			if addr == nil {
				a4, a6, err := p.getAddrs()
				if err != nil || (len(a4)+len(a6) == 0) {
					return fmt.Errorf("unknown host: %s", p.id)
				}
				for _, a := range a4 {
					if a == nil {
						return fmt.Errorf("invalid address return in lookup: %s", a)
					}
				}
				for _, a := range a6 {
					if a == nil {
						return fmt.Errorf("invalid address return in lookup: %s", a)
					}
				}
			}
		case filterProtocolEther:
			if _, err := net.ParseMAC(p.id); err != nil {
				return fmt.Errorf("invalid ethernet address: %s", p.id)
			}
		}
	case p.kind == filterKindMulticast:
		switch p.protocol {
		case filterProtocolUnset, filterProtocolEther, filterProtocolIP, filterProtocolIP6:
		default:
			return fmt.Errorf("multicast not supported for protocol")
		}
	case p.kind == filterKindUnset && p.protocol == filterProtocolUnset && p.subProtocol == filterSubProtocolUnset:
		return fmt.Errorf("parse error")
	case p.kind == filterKindPort:
		if _, err := findPort(p.id); err != nil {
			return err
		}
	case p.kind == filterKindNet:
		addr, network, err := getNetAndMask(p.id)
		if err != nil {
			return err
		}
		masked := addr.Mask(network.Mask)
		if !addr.Equal(masked) {
			return fmt.Errorf("invalid network, network bits extend past mask bits: %s", p.id)
		}
	case p.kind == filterKindUnset && p.protocol == filterProtocolEther && p.subProtocol == filterSubProtocolUnset:
		return fmt.Errorf("parse error")
	}
	return nil
}

func (p primitive) getAddrs() ([]net.IP, []net.IP, error) {
	a6, a4, addrs := []net.IP{}, []net.IP{}, []net.IP{}
	if addr := net.ParseIP(p.id); addr != nil {
		addrs = append(addrs, addr)
	} else {
		resolvedAddrs, _ := resolver.LookupHost(context.Background(), p.id)
		for _, a := range resolvedAddrs {
			addrs = append(addrs, net.ParseIP(a))
		}
	}
	for _, a := range addrs {
		if a.To4() != nil {
			a4 = append(a4, a)
		} else {
			a6 = append(a6, a)
		}
	}
	return a4, a6, nil
}

func findPort(portStr string) (int, error) {
	if port, err := strconv.Atoi(portStr); err == nil {
		return port, nil
	}
	if port, err := net.LookupPort("tcp", portStr); err == nil {
		return port, nil
	}
	if port, err := net.LookupPort("udp", portStr); err == nil {
		return port, nil
	}
	return -1, fmt.Errorf("invalid port: %s", portStr)
}
