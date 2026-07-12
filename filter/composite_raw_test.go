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

func TestMulticastAndUdpRAW_L2Only(t *testing.T) {
	_, err := Compile("multicast and udp", LinkTypeRaw)
	if !errors.Is(err, ErrL2OnlyLinkType) {
		t.Fatalf("expected ErrL2OnlyLinkType, got %v", err)
	}
}

func TestMulticastOrUdpRAW(t *testing.T) {
	insns, err := Compile("multicast or udp", LinkTypeRaw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(insns) <= 2 {
		t.Fatalf("expected more than 2 instructions for udp, got %d: %v", len(insns), insns)
	}
}

// TestCompositeOrRejectLastRAW guards against the always-false member appearing
// as the LAST operand of an OR on RAW. arp is always-false on RAW, so the
// expression must reduce to "ip host 1.2.3.4"; a packet matching neither operand
// must be rejected. Previously composite.emit used a static last-index that
// ignored skipped trailing members, aliasing the miss path onto returnKeep.
func TestCompositeOrRejectLastRAW(t *testing.T) {
	insns, err := Compile("ip host 1.2.3.4 or arp", LinkTypeRaw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	vm, err := bpf.NewVM(insns)
	if err != nil {
		t.Fatalf("NewVM: %v", err)
	}
	mkUDP := func(d4 byte) []byte {
		pkt := make([]byte, 40)
		pkt[0] = 0x45
		pkt[9] = 17
		pkt[16], pkt[17], pkt[18], pkt[19] = 1, 2, 3, d4
		return pkt
	}
	if out, err := vm.Run(mkUDP(4)); err != nil || out == 0 {
		t.Errorf("dst 1.2.3.4 should match (out=%d err=%v)", out, err)
	}
	if out, err := vm.Run(mkUDP(9)); err != nil || out != 0 {
		t.Errorf("dst 1.2.3.9 matches neither operand, must reject (out=%d err=%v)", out, err)
	}
}
