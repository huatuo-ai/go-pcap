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
	"golang.org/x/net/bpf"
)

type labelID int32

const (
	labelInvalid labelID = -1
	labelKeep    labelID = -2
	labelFail    labelID = -3
)

type instKind uint8

const (
	instPlain instKind = iota
	instJump
	instJumpIf
	instJumpIfX
)

type pendingInst struct {
	inst    bpf.Instruction
	kind    instKind
	targetT labelID
	targetF labelID
}
