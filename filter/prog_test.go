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

func pnew() *prog { return newProg(ethernetLayout{}) }

func TestProgEmpty(t *testing.T) {
	p := pnew()
	out, err := p.finalize()
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 sentinel instructions, got %d", len(out))
	}
	if out[0] != returnKeep || out[1] != returnDrop {
		t.Fatalf("expected [returnKeep, returnDrop], got %v", out)
	}
}

func TestProgSingleJumpIfKeepFail(t *testing.T) {
	p := pnew()
	p.emit(bpf.LoadAbsolute{Off: 12, Size: 2})
	p.emitJumpIf(bpf.JumpEqual, 0x0800, labelKeep, labelFail)
	out, err := p.finalize()
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if len(out) != 4 {
		t.Fatalf("expected 4 instructions, got %d", len(out))
	}
	j, ok := out[1].(bpf.JumpIf)
	if !ok {
		t.Fatalf("expected JumpIf at idx 1, got %T", out[1])
	}
	// idx 1 → returnKeep@2: skipTrue = 2-1-1 = 0; returnDrop@3: skipFalse = 3-1-1 = 1
	if j.SkipTrue != 0 || j.SkipFalse != 1 {
		t.Fatalf("expected SkipTrue=0 SkipFalse=1, got %d %d", j.SkipTrue, j.SkipFalse)
	}
	if out[2] != returnKeep || out[3] != returnDrop {
		t.Fatalf("sentinel mismatch")
	}
}

func TestProgLocalLabelForwardJump(t *testing.T) {
	p := pnew()
	isIPv4 := p.newLabel()
	p.emit(bpf.LoadAbsolute{Off: 12, Size: 2})
	p.emitJumpIf(bpf.JumpEqual, 0x0800, isIPv4, labelFail)
	p.bind(isIPv4)
	p.emit(bpf.LoadAbsolute{Off: 26, Size: 4})
	p.emitJumpIf(bpf.JumpEqual, 0x0A000001, labelKeep, labelFail)

	out, err := p.finalize()
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if len(out) != 6 {
		t.Fatalf("expected 6 instructions, got %d", len(out))
	}
	// idx 1: JumpIf → isIPv4(2): skipTrue = 2-1-1 = 0; labelFail(5): skipFalse = 5-1-1 = 3
	j1 := out[1].(bpf.JumpIf)
	if j1.SkipTrue != 0 || j1.SkipFalse != 3 {
		t.Fatalf("idx 1: expected SkipTrue=0 SkipFalse=3, got %d %d", j1.SkipTrue, j1.SkipFalse)
	}
	// idx 3: JumpIf → labelKeep(4): skipTrue = 4-3-1 = 0; labelFail(5): skipFalse = 5-3-1 = 1
	j3 := out[3].(bpf.JumpIf)
	if j3.SkipTrue != 0 || j3.SkipFalse != 1 {
		t.Fatalf("idx 3: expected SkipTrue=0 SkipFalse=1, got %d %d", j3.SkipTrue, j3.SkipFalse)
	}
}

func TestProgMultipleLabelsSamePosition(t *testing.T) {
	p := pnew()
	done := p.newLabel()
	merge := p.newLabel()
	p.emitJumpIf(bpf.JumpEqual, 1, done, merge)
	p.bind(done)
	p.bind(merge)
	p.emit(bpf.LoadAbsolute{Off: 0, Size: 1})
	out, err := p.finalize()
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	// idx 0: JumpIf → done/merge both at idx 1
	j := out[0].(bpf.JumpIf)
	if j.SkipTrue != 0 || j.SkipFalse != 0 {
		t.Fatalf("expected SkipTrue=0 SkipFalse=0, got %d %d", j.SkipTrue, j.SkipFalse)
	}
}

func TestProgBindAfterEmit(t *testing.T) {
	p := pnew()
	cont := p.newLabel()
	p.emit(bpf.LoadAbsolute{Off: 0, Size: 1})
	p.bind(cont) // binds to idx 1, which will be returnKeep in finalize
	// No more emits; cont resolves to the returnKeep sentinel slot
	out, err := p.finalize()
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	// cont was bound to pos=1; returnKeep is at idx 1, returnDrop at idx 2
	_ = out // just verify no error
}

func TestProgUnboundLabel(t *testing.T) {
	p := pnew()
	ghost := p.newLabel()
	p.emitJumpIf(bpf.JumpEqual, 0, ghost, labelKeep)
	_, err := p.finalize()
	if err == nil {
		t.Fatal("expected error for unbound label")
	}
	var ue unboundLabelError
	if !errors.As(err, &ue) {
		t.Fatalf("expected unboundLabelError, got %T: %v", err, err)
	}
}

func TestProgBackwardJump(t *testing.T) {
	p := pnew()
	back := p.newLabel()
	p.emit(bpf.LoadAbsolute{Off: 0, Size: 1})
	p.bind(back)
	p.emitJumpIf(bpf.JumpEqual, 0, back, labelKeep) // backward: back@0, from idx 2
	_, err := p.finalize()
	if err == nil {
		t.Fatal("expected error for backward jump")
	}
	var bj backwardJumpError
	if !errors.As(err, &bj) {
		t.Fatalf("expected backwardJumpError, got %T: %v", err, err)
	}
}

func TestProgSkipOverflow(t *testing.T) {
	p := pnew()
	far := p.newLabel()
	// Emit 257 plain instructions so the jump at idx 0 has skip > 255
	p.emitJumpIf(bpf.JumpEqual, 0, far, labelKeep)
	for i := 0; i < 257; i++ {
		p.emit(bpf.LoadAbsolute{Off: uint32(i), Size: 1})
	}
	p.bind(far)
	_, err := p.finalize()
	if err == nil {
		t.Fatal("expected error for skip overflow")
	}
	var so skipOverflowError
	if !errors.As(err, &so) {
		t.Fatalf("expected skipOverflowError, got %T: %v", err, err)
	}
}

func TestProgDuplicateBind(t *testing.T) {
	p := pnew()
	l := p.newLabel()
	p.bind(l)
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for duplicate bind")
		}
	}()
	p.bind(l)
}

func TestProgBindReservedLabel(t *testing.T) {
	for _, l := range []labelID{labelKeep, labelFail, labelInvalid} {
		p := pnew()
		defer func() {
			if r := recover(); r == nil {
				t.Fatalf("expected panic for bind of reserved label %d", l)
			}
		}()
		p.bind(l)
	}
}

func TestProgDoubleFinalize(t *testing.T) {
	p := pnew()
	_, err := p.finalize()
	if err != nil {
		t.Fatalf("first finalize: %v", err)
	}
	_, err = p.finalize()
	var af alreadyFinalizedError
	if !errors.As(err, &af) {
		t.Fatalf("expected alreadyFinalizedError, got %T: %v", err, err)
	}
}

func TestProgEmitJumpDirect(t *testing.T) {
	p := pnew()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for emit of jump instruction")
		}
	}()
	p.emit(bpf.Jump{Skip: 1})
}
