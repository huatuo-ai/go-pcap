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
	"testing"

	"golang.org/x/net/bpf"
)

func TestDLT_RAW_ipHost(t *testing.T) {
	insns, err := Compile("ip host 10.0.0.1", LinkTypeRaw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []bpf.Instruction{
		// genLinkProbe for RAW: load first byte, mask version nibble
		bpf.LoadAbsolute{Off: 0, Size: 1},
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xF0},
		// genLinkType for IPv4: compare nibble 0x40
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40, SkipFalse: 5},
		// IPv4 src/dst check
		bpf.LoadAbsolute{Off: 12, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0a000001, SkipTrue: 2},
		bpf.LoadAbsolute{Off: 16, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0a000001, SkipFalse: 1},
		bpf.RetConstant{Val: 0x40000},
		bpf.RetConstant{Val: 0},
	}
	compareInstructionsOrFail(t, insns, expected)
}

func TestDLT_RAW_ip6Host(t *testing.T) {
	insns, err := Compile("ip6 host 2a00:1450:4001:824::2004", LinkTypeRaw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(insns) < 5 {
		t.Fatalf("too few instructions: %d", len(insns))
	}
	// First instruction: load byte 0 (version field)
	if insns[0] != (bpf.LoadAbsolute{Off: 0, Size: 1}) {
		t.Errorf("insn[0]: expected LoadAbs{0,1}, got %v", insns[0])
	}
	// Second: AND 0xF0 (version nibble mask)
	if insns[1] != (bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xF0}) {
		t.Errorf("insn[1]: expected AND #0xF0, got %v", insns[1])
	}
	// Third: JumpIf Eq 0x60 (IPv6 version nibble)
	if insns[2].(bpf.JumpIf).Val != 0x60 {
		t.Errorf("insn[2]: expected JumpIf Eq #0x60, got %v", insns[2])
	}
}

func TestDLT_RAW_tcpPort(t *testing.T) {
	insns, err := Compile("tcp port 80", LinkTypeRaw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(insns) < 10 {
		t.Fatalf("too few instructions: %d", len(insns))
	}
	// Version nibble probe
	if insns[0] != (bpf.LoadAbsolute{Off: 0, Size: 1}) {
		t.Errorf("insn[0]: expected LoadAbs{0,1}, got %v", insns[0])
	}
	if insns[1] != (bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xF0}) {
		t.Errorf("insn[1]: expected AND #0xF0, got %v", insns[1])
	}
}

func TestDLT_RAW_udp(t *testing.T) {
	insns, err := Compile("udp", LinkTypeRaw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(insns) < 6 {
		t.Fatalf("too few instructions: %d", len(insns))
	}
	// Version nibble probe followed by ip6+ip4 checks
}

func TestDLT_RAW_unsetHost(t *testing.T) {
	// "host 10.0.0.1" with unset protocol on RAW: should use IP version nibble
	insns, err := Compile("host 10.0.0.1", LinkTypeRaw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(insns) < 5 {
		t.Fatalf("too few instructions: %d", len(insns))
	}
	// No arp/rarp branches on RAW
	// Should have ip4 nibble check and ip4 address check only
	if insns[0] != (bpf.LoadAbsolute{Off: 0, Size: 1}) {
		t.Errorf("insn[0]: expected LoadAbs{0,1}, got %v", insns[0])
	}
}

func TestDLT_RAW_net(t *testing.T) {
	insns, err := Compile("net 1.2.3.0/24", LinkTypeRaw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(insns) < 5 {
		t.Fatalf("too few instructions: %d", len(insns))
	}
	// Should have ip4 nibble check
	if insns[0] != (bpf.LoadAbsolute{Off: 0, Size: 1}) {
		t.Errorf("insn[0]: expected LoadAbs{0,1}, got %v", insns[0])
	}
}

func TestDLT_RAW_l2Only(t *testing.T) {
	// Pure L2-only expressions on RAW: Compile detects 2-instruction always-false
	// and returns ErrL2OnlyLinkType so callers can substitute reject-all.
	l2OnlyExprs := []string{
		"arp",
		"rarp",
		"ether host aa:bb:cc:dd:ee:ff",
	}
	for _, expr := range l2OnlyExprs {
		t.Run(expr, func(t *testing.T) {
			_, err := Compile(expr, LinkTypeRaw)
			if !errors.Is(err, ErrL2OnlyLinkType) {
				t.Errorf("expected ErrL2OnlyLinkType for %q, got %v", expr, err)
			}
		})
	}
	// L2 primitive in a composite with L3-capable terms: should compile
	// (the L2 part becomes always-false via genLinkType with nibble 0xF0)
	_, err := Compile("arp or ip host 1.2.3.4", LinkTypeRaw)
	if err != nil {
		t.Fatalf("unexpected error for composite: %v", err)
	}
}

func TestSizeInvariant(t *testing.T) {
	testCases := []struct {
		expr string
		lt   LinkType
	}{
		{"ip host 10.0.0.1", LinkTypeEthernet},
		{"ip host 10.0.0.1", LinkTypeRaw},
		{"ip6 host 2a00:1450:4001:824::2004", LinkTypeEthernet},
		{"ip6 host 2a00:1450:4001:824::2004", LinkTypeRaw},
		{"tcp port 80", LinkTypeEthernet},
		{"tcp port 80", LinkTypeRaw},
		{"udp", LinkTypeEthernet},
		{"udp", LinkTypeRaw},
		{"host 10.0.0.1", LinkTypeEthernet},
		{"host 10.0.0.1", LinkTypeRaw},
		{"net 1.2.3.0/24", LinkTypeEthernet},
		{"net 1.2.3.0/24", LinkTypeRaw},
		{"port 22", LinkTypeEthernet},
		{"port 22", LinkTypeRaw},
	}
	for _, tc := range testCases {
		t.Run(tc.expr+"_"+ltName(tc.lt), func(t *testing.T) {
			insns, err := Compile(tc.expr, tc.lt)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			expectedSize, err := Size(tc.expr, tc.lt)
			if err != nil {
				t.Fatalf("Size error: %v", err)
			}
			if len(insns) != expectedSize {
				t.Errorf("size invariant violated: len(Compile)=%d, Size=%d", len(insns), expectedSize)
			}
		})
	}
}

func compareInstructionsOrFail(t *testing.T, got, want []bpf.Instruction) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("instruction count mismatch: got %d, want %d\ngot:  %v\nwant: %v", len(got), len(want), got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("insn[%d]: got %v, want %v", i, got[i], want[i])
		}
	}
}

func ltName(lt LinkType) string {
	switch lt {
	case LinkTypeEthernet:
		return "EN10MB"
	case LinkTypeRaw:
		return "RAW"
	default:
		return "?"
	}
}
