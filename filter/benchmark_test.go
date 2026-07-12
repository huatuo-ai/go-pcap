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

var benchmarkExpressions = []struct {
	name string
	expr string
}{
	{"simple", "tcp"},
	{"medium", "tcp and port 443 or udp and port 53"},
	{"complex", "(ip6 and udp and port 53) or (ip and src net 192.0.2.0/24 and not tcp)"},
}

func BenchmarkExpressionParse(b *testing.B) {
	for _, tc := range benchmarkExpressions {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				e := NewExpression(tc.expr)
				if f := e.Compile(); f == nil {
					b.Fatal("nil filter")
				}
			}
		})
	}
}

func BenchmarkCompile(b *testing.B) {
	for _, link := range []struct {
		name string
		link LinkType
	}{
		{"ethernet", LinkTypeEthernet},
		{"raw", LinkTypeRaw},
	} {
		for _, tc := range benchmarkExpressions {
			b.Run(link.name+"/"+tc.name, func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					if _, err := Compile(tc.expr, link.link); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func BenchmarkSize(b *testing.B) {
	for _, tc := range benchmarkExpressions {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := Size(tc.expr, LinkTypeEthernet); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkVMRun(b *testing.B) {
	packets := behaviorPacketCorpus(b)
	tests := []struct {
		name   string
		expr   string
		link   LinkType
		packet []byte
	}{
		{"ethernet-match", "tcp and port 80 or udp", LinkTypeEthernet, packets["ip4-tcp-80"]},
		{"ethernet-miss", "tcp and port 80 or udp", LinkTypeEthernet, packets["ip4-tcp-443"]},
		{"raw-match", "tcp and port 80 or udp", LinkTypeRaw, rawBehaviorPacket(b, packets["ip4-udp-53"])},
		{"raw-miss", "tcp and port 80", LinkTypeRaw, rawBehaviorPacket(b, packets["ip4-tcp-443"])},
	}

	for _, tc := range tests {
		b.Run(tc.name, func(b *testing.B) {
			insns, err := Compile(tc.expr, tc.link)
			if err != nil {
				b.Fatal(err)
			}
			vm, err := bpf.NewVM(insns)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := vm.Run(tc.packet); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
