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

	"golang.org/x/net/bpf"
)

// LinkType enumerates supported data-link types.
// LinkTypeEthernet is the zero value and serves as the default.
type LinkType uint32

const (
	LinkTypeEthernet LinkType = iota // DLT_EN10MB
	LinkTypeRaw                      // DLT_RAW
)

// Sentinel errors.
var (
	ErrEmptyFilter         = errors.New("filter: empty expression")
	ErrInvalidFilter       = errors.New("filter: invalid expression")
	ErrUnsupportedLinkType = errors.New("filter: unsupported link type")
	ErrL2OnlyLinkType      = errors.New("filter: expression matches only L2 protocols on non-L2 link type")
)

// linkLayout abstracts per-link-type packet layout.
// Concrete implementations are ethernetLayout and rawLayout, selected
// by layoutFor through an explicit switch (closed set, no registry).
type linkLayout interface {
	// l3Off returns the byte offset from packet start to the L3 (IP) header.
	l3Off() uint32

	// genLinkProbe returns instructions that load the link-layer type into A.
	genLinkProbe() []bpf.Instruction

	// genLinkType returns a JumpIf comparing A against the link-type value
	// for proto. st/sf are relative skip offsets.
	genLinkType(proto uint32, st, sf uint8) bpf.Instruction

	// linkProbeSize returns len(genLinkProbe()).
	linkProbeSize() uint8

	// linkCompareSize returns 1 (the JumpIf from genLinkType).
	linkCompareSize() uint8

	// hasL2Protocols reports whether this link type carries L2 protocols
	// (arp, rarp, ether).
	hasL2Protocols() bool
}

// ethernetLayout implements linkLayout for DLT_EN10MB.
type ethernetLayout struct{}

func (e ethernetLayout) l3Off() uint32        { return 14 }
func (e ethernetLayout) linkProbeSize() uint8 { return 1 }
func (e ethernetLayout) hasL2Protocols() bool { return true }

func (e ethernetLayout) genLinkProbe() []bpf.Instruction {
	return []bpf.Instruction{bpf.LoadAbsolute{Off: 12, Size: 2}}
}

func (e ethernetLayout) linkCompareSize() uint8 { return 1 }

func (e ethernetLayout) genLinkType(proto uint32, st, sf uint8) bpf.Instruction {
	return bpf.JumpIf{Cond: bpf.JumpEqual, Val: proto, SkipTrue: st, SkipFalse: sf}
}
