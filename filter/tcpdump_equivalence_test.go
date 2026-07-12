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
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/net/bpf"
)

func tcpdumpInstructions(expr, dlt string) ([]bpf.Instruction, error) {
	out, err := exec.Command("tcpdump", "-y", dlt, "-ddd", expr).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("tcpdump -y %s -ddd %q: %w\n%s", dlt, expr, err, out)
	}

	lines := strings.Fields(strings.TrimSpace(string(out)))
	if len(lines) == 0 {
		return nil, fmt.Errorf("tcpdump returned no instructions for %q", expr)
	}
	want, err := strconv.Atoi(lines[0])
	if err != nil {
		return nil, fmt.Errorf("parse instruction count %q: %w", lines[0], err)
	}
	if len(lines) != 1+want*4 {
		return nil, fmt.Errorf("tcpdump returned %d fields for %d instructions", len(lines), want)
	}

	raw := make([]bpf.RawInstruction, want)
	for i := range raw {
		base := 1 + i*4
		op, err := strconv.ParseUint(lines[base], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("parse op %q: %w", lines[base], err)
		}
		jt, err := strconv.ParseUint(lines[base+1], 10, 8)
		if err != nil {
			return nil, fmt.Errorf("parse jt %q: %w", lines[base+1], err)
		}
		jf, err := strconv.ParseUint(lines[base+2], 10, 8)
		if err != nil {
			return nil, fmt.Errorf("parse jf %q: %w", lines[base+2], err)
		}
		k, err := strconv.ParseUint(lines[base+3], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("parse k %q: %w", lines[base+3], err)
		}
		raw[i] = bpf.RawInstruction{Op: uint16(op), Jt: uint8(jt), Jf: uint8(jf), K: uint32(k)}
	}

	insns, decoded := bpf.Disassemble(raw)
	if !decoded {
		return nil, fmt.Errorf("tcpdump program for %q has unsupported instructions", expr)
	}
	return insns, nil
}

func TestTCPDumpDecisionEquivalence(t *testing.T) {
	if _, err := exec.LookPath("tcpdump"); err != nil {
		t.Skip("tcpdump is not installed")
	}

	packets := behaviorPacketCorpus(t)
	tests := []struct {
		name    string
		expr    string
		link    LinkType
		dlt     string
		packets []string
	}{
		{
			name: "ethernet",
			link: LinkTypeEthernet,
			dlt:  "EN10MB",
			packets: []string{
				"ip4-tcp-80", "ip4-tcp-443", "ip4-udp-53", "ip4-icmp",
				"ip4-multicast", "ip6-udp-53", "arp-request",
			},
			expr: "tcp and port 80 or udp",
		},
		{
			name: "ethernet host and multicast",
			link: LinkTypeEthernet,
			dlt:  "EN10MB",
			packets: []string{
				"ip4-tcp-80", "ip4-udp-53", "ip4-multicast", "ip6-udp-53", "arp-request",
			},
			expr: "host 10.0.0.1 or ip multicast",
		},
		{
			name: "ethernet negation",
			link: LinkTypeEthernet,
			dlt:  "EN10MB",
			packets: []string{
				"ip4-tcp-80", "ip4-udp-53", "ip4-icmp", "ip6-udp-53", "arp-request",
			},
			expr: "not tcp",
		},
		{
			name: "raw",
			link: LinkTypeRaw,
			dlt:  "RAW",
			packets: []string{
				"ip4-tcp-80", "ip4-tcp-443", "ip4-udp-53", "ip4-icmp", "ip4-multicast", "ip6-udp-53",
			},
			expr: "tcp and port 80 or udp",
		},
		{
			name: "raw IPv6",
			link: LinkTypeRaw,
			dlt:  "RAW",
			packets: []string{
				"ip4-tcp-80", "ip4-udp-53", "ip4-icmp", "ip6-udp-53",
			},
			expr: "ip6 and udp and port 53",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ours, err := Compile(tt.expr, tt.link)
			if err != nil {
				t.Fatalf("Compile(%q): %v", tt.expr, err)
			}
			reference, err := tcpdumpInstructions(tt.expr, tt.dlt)
			if err != nil {
				t.Fatal(err)
			}
			ourVM, err := bpf.NewVM(ours)
			if err != nil {
				t.Fatalf("our VM: %v", err)
			}
			referenceVM, err := bpf.NewVM(reference)
			if err != nil {
				t.Fatalf("tcpdump VM: %v", err)
			}

			for _, name := range tt.packets {
				packet := packets[name]
				if tt.link == LinkTypeRaw {
					packet = rawBehaviorPacket(t, packet)
				}
				got, err := ourVM.Run(packet)
				if err != nil {
					t.Fatalf("our VM on %s: %v", name, err)
				}
				want, err := referenceVM.Run(packet)
				if err != nil {
					t.Fatalf("tcpdump VM on %s: %v", name, err)
				}
				if (got != 0) != (want != 0) {
					t.Errorf("%s: ours=%d tcpdump=%d\nours:    %v\ntcpdump: %v", name, got, want, ours, reference)
				}
			}
		})
	}
}
