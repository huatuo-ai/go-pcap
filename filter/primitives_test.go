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
)

func TestPrimitivesCombine(t *testing.T) {
	tests := []struct {
		in, out primitives
	}{
		// NON-COMBINABLE
		// single
		{
			primitives{
				primitive{
					kind:      filterKindHost,
					direction: filterDirectionUnset,
					protocol:  filterProtocolUnset,
					id:        "abc",
				},
			},
			primitives{
				primitive{
					kind:      filterKindHost,
					direction: filterDirectionUnset,
					protocol:  filterProtocolUnset,
					id:        "abc",
				},
			},
		},
		// double
		{
			primitives{
				primitive{
					kind:      filterKindHost,
					direction: filterDirectionUnset,
					protocol:  filterProtocolUnset,
					id:        "abc",
				}, primitive{
					kind:      filterKindHost,
					direction: filterDirectionUnset,
					protocol:  filterProtocolUnset,
					id:        "def",
				},
			},
			primitives{
				primitive{
					kind:      filterKindHost,
					direction: filterDirectionUnset,
					protocol:  filterProtocolUnset,
					id:        "abc",
				}, primitive{
					kind:      filterKindHost,
					direction: filterDirectionUnset,
					protocol:  filterProtocolUnset,
					id:        "def",
				},
			},
		},
		// triple
		{
			primitives{
				primitive{
					kind:      filterKindHost,
					direction: filterDirectionUnset,
					protocol:  filterProtocolUnset,
					id:        "abc",
				}, primitive{
					kind:      filterKindHost,
					direction: filterDirectionUnset,
					protocol:  filterProtocolUnset,
					id:        "def",
				}, primitive{
					kind:      filterKindPort,
					direction: filterDirectionSrc,
					protocol:  filterProtocolUnset,
					id:        "25",
				},
			},
			primitives{
				primitive{
					kind:      filterKindHost,
					direction: filterDirectionUnset,
					protocol:  filterProtocolUnset,
					id:        "abc",
				}, primitive{
					kind:      filterKindHost,
					direction: filterDirectionUnset,
					protocol:  filterProtocolUnset,
					id:        "def",
				}, primitive{
					kind:      filterKindPort,
					direction: filterDirectionSrc,
					protocol:  filterProtocolUnset,
					id:        "25",
				},
			},
		},

		// COMBINABLE
		// "host abc and src" -> "host src abc"
		{
			primitives{
				primitive{
					kind:      filterKindHost,
					direction: filterDirectionUnset,
					protocol:  filterProtocolUnset,
					id:        "abc",
				}, primitive{
					kind:      filterKindUnset,
					direction: filterDirectionSrc,
					protocol:  filterProtocolUnset,
					id:        "abc",
				},
			},
			primitives{
				primitive{
					kind:      filterKindHost,
					direction: filterDirectionSrc,
					protocol:  filterProtocolUnset,
					id:        "abc",
				},
			},
		},
	}
	for i, tt := range tests {
		out := tt.in.combine()
		if !out.equal(&tt.out) {
			t.Errorf("%d: mismatched\nactual %#v\nexpected %#v", i, tt.in, tt.out)
		}
	}
}
