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

func TestCompileLinuxSocketVLANUsesKernelMetadata(t *testing.T) {
	t.Parallel()

	live, err := CompileWithOptions("vlan 3", CompileOptions{
		LinkType: LinkTypeEthernet,
		Target:   CompileTargetLinuxSocket,
	})
	if err != nil {
		t.Fatalf("CompileWithOptions(linux socket): %v", err)
	}
	if _, err := bpf.Assemble(live); err != nil {
		t.Fatalf("assemble linux socket filter: %v", err)
	}
	if !hasLoadAbsolute(live, linuxBPFExtVLANTagPresent, lengthByte) {
		t.Fatalf("linux socket filter does not load VLAN_TAG_PRESENT")
	}
	if !hasLoadAbsolute(live, linuxBPFExtVLANTag, lengthHalf) {
		t.Fatalf("linux socket filter does not load VLAN_TAG")
	}

	portable, err := Compile("vlan 3", LinkTypeEthernet)
	if err != nil {
		t.Fatalf("Compile(portable): %v", err)
	}
	if hasLoadAbsolute(portable, linuxBPFExtVLANTagPresent, lengthByte) ||
		hasLoadAbsolute(portable, linuxBPFExtVLANTag, lengthHalf) {
		t.Fatalf("portable filter unexpectedly contains Linux socket VLAN metadata loads")
	}
}

func TestCompileLinuxSocketVLANAndARPKeepsMetadataAndInlinePaths(t *testing.T) {
	t.Parallel()

	insns, err := CompileWithOptions("vlan 3 and arp", CompileOptions{
		LinkType: LinkTypeEthernet,
		Target:   CompileTargetLinuxSocket,
	})
	if err != nil {
		t.Fatalf("CompileWithOptions(linux socket): %v", err)
	}
	if _, err := bpf.Assemble(insns); err != nil {
		t.Fatalf("assemble linux socket filter: %v", err)
	}
	if !hasLoadCompare(insns, 12, lengthHalf, etherTypeArp) {
		t.Fatalf("linux socket metadata path does not check inner ARP at ethernet offset 12")
	}
	if !hasLoadCompare(insns, 16, lengthHalf, etherTypeArp) {
		t.Fatalf("linux socket inline VLAN fallback path does not check inner ARP at ethernet offset 16")
	}
}

func hasLoadAbsolute(insns []bpf.Instruction, offset uint32, size int) bool {
	for _, insn := range insns {
		load, ok := insn.(bpf.LoadAbsolute)
		if ok && load.Off == offset && load.Size == size {
			return true
		}
	}
	return false
}

func hasLoadCompare(insns []bpf.Instruction, offset uint32, size int, value uint32) bool {
	for i := 0; i+1 < len(insns); i++ {
		load, ok := insns[i].(bpf.LoadAbsolute)
		if !ok || load.Off != offset || load.Size != size {
			continue
		}
		jump, ok := insns[i+1].(bpf.JumpIf)
		if ok && jump.Cond == bpf.JumpEqual && jump.Val == value {
			return true
		}
	}
	return false
}
