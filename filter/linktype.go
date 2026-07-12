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
