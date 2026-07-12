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
	"testing"

	"golang.org/x/net/bpf"
)

func TestExpressionEmpty(t *testing.T) {
	e := NewExpression("")
	if e != nil {
		t.Error("expected nil for blank expression")
	}
}

func TestExpressionHasNext(t *testing.T) {
	// single element
	e := NewExpression("a")
	if !e.HasNext() {
		t.Fatal("with one element remaining, should have HasNext()==true")
	}
	e.Next()
	if e.HasNext() {
		t.Fatal("with zero element remaining, should have HasNext()==false")
	}
}

func TestExpressionNextJoiner(t *testing.T) {
	tests := []struct {
		filter string
		etype  ElementType
		and    bool
	}{
		{"and", Joiner, true},
		{"or", Joiner, false},
		{"abc", Primitive, false},
	}
	for i, tt := range tests {
		e := NewExpression(tt.filter)
		f := e.Next()
		if f.Type() != tt.etype {
			t.Fatalf("%d: mismatched IsPrimitive, actual %v, expected %v", i, f.Type(), tt.etype)
		}
		if tt.etype != Joiner {
			continue
		}
		val := f.(*and)
		if bool(*val) != tt.and {
			t.Fatalf("%d: mismatched value, actual %v, expected %v", i, *val, tt.and)
		}
	}
}

// TestExpressionNextPrimitive tests Expression.Next(). This could be combined
// with the lists at testCasesExpressionFilterInstructions, but that includes
// setting defaults, which is a separate step
func TestExpressionNextPrimitive(t *testing.T) {
	tests := []struct {
		expression string
		prim       primitive
	}{
		{"abc", primitive{
			kind:      filterKindUnset,
			direction: filterDirectionUnset,
			protocol:  filterProtocolUnset,
			id:        "abc",
		}},
		{"host", primitive{
			kind:      filterKindHost,
			direction: filterDirectionUnset,
			protocol:  filterProtocolUnset,
			id:        "",
		}},
		{"host abc", primitive{
			kind:      filterKindHost,
			direction: filterDirectionUnset,
			protocol:  filterProtocolUnset,
			id:        "abc",
		}},
		{"src host abc", primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrc,
			protocol:  filterProtocolUnset,
			id:        "abc",
		}},
		{"dst host abc", primitive{
			kind:      filterKindHost,
			direction: filterDirectionDst,
			protocol:  filterProtocolUnset,
			id:        "abc",
		}},
		{"src or dst host abc", primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrcOrDst,
			protocol:  filterProtocolUnset,
			id:        "abc",
		}},
		{"src and dst host abc", primitive{
			kind:      filterKindHost,
			direction: filterDirectionSrcAndDst,
			protocol:  filterProtocolUnset,
			id:        "abc",
		}},
		{"port 22", primitive{
			kind:      filterKindPort,
			direction: filterDirectionUnset,
			protocol:  filterProtocolUnset,
			id:        "22",
		}},
		{"src port 22", primitive{
			kind:      filterKindPort,
			direction: filterDirectionSrc,
			protocol:  filterProtocolUnset,
			id:        "22",
		}},
		{"net 192.168.0.0/24", primitive{
			kind:      filterKindNet,
			direction: filterDirectionUnset,
			protocol:  filterProtocolUnset,
			id:        "192.168.0.0/24",
		}},
		{"src net 192.168.0.0/24", primitive{
			kind:      filterKindNet,
			direction: filterDirectionSrc,
			protocol:  filterProtocolUnset,
			id:        "192.168.0.0/24",
		}},
		{"ip proto tcp", primitive{
			kind:        filterKindUnset,
			direction:   filterDirectionUnset,
			protocol:    filterProtocolIP,
			subProtocol: filterSubProtocolTCP,
			id:          "",
		}},
	}
	for _, tt := range tests {
		e := NewExpression(tt.expression)
		f := e.Next()
		val := f.(primitive)
		if !val.Equal(tt.prim) {
			t.Errorf("%s: mismatched value\nactual   %#v\nexpected %#v", tt.expression, val, tt.prim)
		}
	}
}

func TestExpressionCompile(t *testing.T) {
	for k, v := range testCasesExpressionFilterInstructions {
		t.Run(k, func(t *testing.T) {
			for i, tt := range v {
				e := NewExpression(tt.expression)
				f := e.Compile()
				if !f.Equal(tt.filter) {
					t.Errorf("%d '%s': mismatched value\nactual   %#v\nexpected %#v", i, tt.expression, f, tt.filter)
				}
			}
		})
	}
}

func TestFilterSize(t *testing.T) {
	for k, v := range testCasesExpressionFilterInstructions {
		t.Run(k, func(t *testing.T) {
			for i, tt := range v {
				e := NewExpression(tt.expression)
				filter := e.Compile()
				if tt.err != nil {
					continue
				}
				size := filter.Size(ethernetLayout{})
				if size != uint8(len(tt.instructions)) {
					t.Errorf("%d '%s': mismatched size actual %d, expected %d", i, tt.expression, size, len(tt.instructions))
				}
			}
		})
	}
}

func TestFilterCompile(t *testing.T) {
	for k, v := range testCasesExpressionFilterInstructions {
		t.Run(k, func(t *testing.T) {
			for i, tt := range v {
				e := NewExpression(tt.expression)
				filter := e.Compile()
				inst, err := filter.Compile(ethernetLayout{})
				switch {
				case (err != nil && tt.err == nil) || (err == nil && tt.err != nil) || (err != nil && tt.err != nil && err.Error() != tt.err.Error()):
					t.Errorf("%d '%s': mismatched errors \nActual  : %v\nExpected: %v", i, tt.expression, err, tt.err)
				case !compareInstructions(inst, tt.instructions):
					t.Errorf("%d '%s': mismatched instructions \nActual  : %#v\nExpected: %#v", i, tt.expression, inst, tt.instructions)
				}
			}
		})
	}
}

// compare slices of bpf instruction
func compareInstructions(a, b []bpf.Instruction) bool {
	if len(a) != len(b) {
		return false
	}

	for i, item := range a {
		if item != b[i] {
			return false
		}
	}

	return true
}

// TestExpressionCompilePrecedence verifies that mixed and/or expressions are
// grouped with correct precedence (and binds tighter than or) rather than
// flattened into a single connective.
func TestExpressionCompilePrecedence(t *testing.T) {
	tcp := primitive{direction: filterDirectionSrcOrDst, subProtocol: filterSubProtocolTCP}
	udp := primitive{direction: filterDirectionSrcOrDst, subProtocol: filterSubProtocolUDP}
	udpNot := primitive{direction: filterDirectionSrcOrDst, subProtocol: filterSubProtocolUDP, negator: true}
	ipMulticast := primitive{direction: filterDirectionSrcOrDst, kind: filterKindMulticast, protocol: filterProtocolIP}
	port80 := primitive{direction: filterDirectionSrcOrDst, kind: filterKindPort, id: "80"}
	icmp := primitive{direction: filterDirectionSrcOrDst, subProtocol: filterSubProtocolIcmp}
	igmp := primitive{direction: filterDirectionSrcOrDst, subProtocol: filterSubProtocolIgmp}

	tests := []struct {
		expression string
		filter     Filter
	}{
		// and binds tighter than or: "tcp and udp" groups under the or.
		{"port 80 or tcp and udp", composite{
			and: false,
			filters: Filters{
				port80,
				composite{and: true, filters: Filters{tcp, udp}},
			},
		}},
		// headline case: (tcp and not udp) or not(ip multicast and udp).
		{"tcp and not udp or not (ip multicast and udp)", composite{
			and: false,
			filters: Filters{
				composite{and: true, filters: Filters{tcp, negated{inner: udpNot}}},
				negated{inner: composite{and: true, filters: Filters{ipMulticast, udp}}},
			},
		}},
		// explicit parentheses keep their own scope, unaffected by the change.
		{"udp and (port 53 or port 67)", composite{
			and: true,
			filters: Filters{
				udp,
				composite{and: false, filters: Filters{
					primitive{direction: filterDirectionSrcOrDst, kind: filterKindPort, id: "53"},
					primitive{direction: filterDirectionSrcOrDst, kind: filterKindPort, id: "67"},
				}},
			},
		}},
		// two and-groups joined by or: (tcp and udp) or (icmp and igmp).
		{"tcp and udp or icmp and igmp", composite{
			and: false,
			filters: Filters{
				composite{and: true, filters: Filters{tcp, udp}},
				composite{and: true, filters: Filters{icmp, igmp}},
			},
		}},
		// an and-group in the middle: tcp or (udp and icmp) or igmp.
		{"tcp or udp and icmp or igmp", composite{
			and: false,
			filters: Filters{
				tcp,
				composite{and: true, filters: Filters{udp, icmp}},
				igmp,
			},
		}},
		// a pure multi-term and-run stays a single and-group.
		{"tcp and udp and icmp", composite{
			and:     true,
			filters: Filters{tcp, udp, icmp},
		}},
	}
	for _, tt := range tests {
		e := NewExpression(tt.expression)
		f := e.Compile()
		if !f.Equal(tt.filter) {
			t.Errorf("%q: mismatched AST\nactual   %#v\nexpected %#v", tt.expression, f, tt.filter)
		}
	}
}

// TestCompilePrecedenceBPF proves the precedence fix end-to-end: a mixed
// and/or filter compiles to cBPF that classifies packets the way libpcap
// does. "tcp and port 80 or udp" means (tcp and port 80) or udp, so a TCP
// packet on neither port 80 must be rejected — the old flat-OR bug would have
// accepted it as plain "tcp".
func TestCompilePrecedenceBPF(t *testing.T) {
	insns, err := Compile("tcp and port 80 or udp", LinkTypeRaw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	vm, err := bpf.NewVM(insns)
	if err != nil {
		t.Fatalf("NewVM: %v", err)
	}
	// RAW IPv4 packet: byte 0 = version/IHL, byte 9 = L4 proto, L4 ports at
	// 20/22 for a 20-byte (IHL=5) header.
	mkPkt := func(proto byte, sport, dport uint16) []byte {
		pkt := make([]byte, 40)
		pkt[0] = 0x45 // IPv4, IHL=5
		pkt[9] = proto
		pkt[20], pkt[21] = byte(sport>>8), byte(sport)
		pkt[22], pkt[23] = byte(dport>>8), byte(dport)
		return pkt
	}
	const (
		protoTCP byte = 6
		protoUDP byte = 17
	)
	tests := []struct {
		name   string
		pkt    []byte
		accept bool
	}{
		{"tcp dst port 80", mkPkt(protoTCP, 1234, 80), true},
		{"tcp src port 80", mkPkt(protoTCP, 80, 1234), true},
		{"tcp neither port 80", mkPkt(protoTCP, 1234, 443), false},
		{"udp any port", mkPkt(protoUDP, 1234, 5000), true},
	}
	for _, tt := range tests {
		out, err := vm.Run(tt.pkt)
		if err != nil {
			t.Fatalf("%s: vm.Run: %v", tt.name, err)
		}
		if got := out != 0; got != tt.accept {
			t.Errorf("%s: accept=%v, want %v (out=%d)", tt.name, got, tt.accept, out)
		}
	}
}
