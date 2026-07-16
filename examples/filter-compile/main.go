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

package main

import (
	"errors"
	"fmt"
	"log"

	"golang.org/x/net/bpf"

	"github.com/huatuo-ai/go-pcap/filter"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	for _, layout := range []struct {
		name     string
		linkType filter.LinkType
	}{
		{
			name:     "EN10MB",
			linkType: filter.LinkTypeEthernet,
		},
		{
			name:     "RAW",
			linkType: filter.LinkTypeRaw,
		},
	} {
		if err := printProgram("ip6 and udp and port 53", layout.name, layout.linkType); err != nil {
			return err
		}
	}

	_, err := filter.Compile("arp", filter.LinkTypeRaw)
	switch {
	case errors.Is(err, filter.ErrL2OnlyLinkType):
		fmt.Println("RAW arp: rejected because arp requires Ethernet framing")
	case err != nil:
		return fmt.Errorf("compile RAW arp: %w", err)
	default:
		return errors.New("RAW arp unexpectedly compiled")
	}

	return nil
}

func printProgram(expr, name string, linkType filter.LinkType) error {
	insns, err := filter.Compile(expr, linkType)
	if err != nil {
		return fmt.Errorf("compile %s for %s: %w", expr, name, err)
	}

	size, err := filter.Size(expr, linkType)
	if err != nil {
		return fmt.Errorf("size %s for %s: %w", expr, name, err)
	}

	raw, err := bpf.Assemble(insns)
	if err != nil {
		return fmt.Errorf("assemble %s for %s: %w", expr, name, err)
	}

	fmt.Printf("%s: Size=%d, cBPF instructions=%d, raw instructions=%d\n", name, size, len(insns), len(raw))
	return nil
}
