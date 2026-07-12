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
	"sort"

	"golang.org/x/net/bpf"
)

// Filter constructed of a tcpdump filter expression
type Filter interface {
	Compile() ([]bpf.Instruction, error)
	Equal(o Filter) bool
	Size() uint8
	IsPrimitive() bool
	Type() ElementType
	Distill() Filter
}

// emitter is the transitional surface of the label-based engine: the pieces
// of Filter the new assembler needs. It merges into Filter itself once every
// node implements it and compilation switches over to link layouts.
type emitter interface {
	emit(b *prog, onMatch, onMiss labelID)
	isAlwaysReject(layout linkLayout) bool
	isAlwaysAccept(layout linkLayout) bool
}

// compileFilter compiles a Filter using the new emit-based assembler. It
// handles the always-accept/always-reject short-circuits, then falls through
// to creating a prog and calling emit.
func compileFilter(f emitter, layout linkLayout) ([]bpf.Instruction, error) {
	if f.isAlwaysReject(layout) {
		return []bpf.Instruction{returnDrop, returnKeep}, nil
	}
	if f.isAlwaysAccept(layout) {
		return []bpf.Instruction{returnKeep, returnDrop}, nil
	}
	b := newProg(layout)
	f.emit(b, labelKeep, labelFail)
	return b.finalize()
}

type ElementType uint8

const (
	Primitive ElementType = iota
	Composite
	Joiner
)

type Element interface {
	Type() ElementType
}

type Filters []Filter

func (f Filters) Len() int {
	return len(f)
}

func (f Filters) Less(i, j int) bool {
	return false
}

func (f Filters) Swap(i, j int) {
	f[i], f[j] = f[j], f[i]
}
func (f Filters) Equal(o Filters) bool {
	// not matched if of the wrong length
	if len(f) != len(o) {
		return false
	}

	// copy so that our sort does not affect the original
	f1 := f[:]
	o1 := o[:]
	sort.Sort(f1)
	sort.Sort(o1)
	for i, val := range f1 {
		if !val.Equal(o1[i]) {
			return false
		}
	}
	return true
}
