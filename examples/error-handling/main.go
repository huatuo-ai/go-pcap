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

	"github.com/huatuo-ai/go-pcap/filter"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cases := []struct {
		name string
		expr string
		link filter.LinkType
	}{
		{
			name: "empty expression",
			expr: "",
			link: filter.LinkTypeEthernet,
		},
		{
			name: "invalid expression",
			expr: "host",
			link: filter.LinkTypeEthernet,
		},
		{
			name: "unsupported link type",
			expr: "ip",
			link: filter.LinkType(99),
		},
		{
			name: "L2-only filter on RAW",
			expr: "arp",
			link: filter.LinkTypeRaw,
		},
	}

	for _, testCase := range cases {
		_, err := filter.Compile(testCase.expr, testCase.link)
		if err == nil {
			return fmt.Errorf("%s unexpectedly compiled", testCase.name)
		}

		fmt.Printf("%s: %s\n", testCase.name, classify(err))
	}

	return nil
}

func classify(err error) string {
	switch {
	case errors.Is(err, filter.ErrEmptyFilter):
		return "provide a non-empty filter expression"
	case errors.Is(err, filter.ErrInvalidFilter):
		return "correct the unsupported or malformed expression"
	case errors.Is(err, filter.ErrUnsupportedLinkType):
		return "choose filter.LinkTypeEthernet or filter.LinkTypeRaw"
	case errors.Is(err, filter.ErrL2OnlyLinkType):
		return "compile L2-only predicates for Ethernet instead of RAW"
	default:
		return fmt.Sprintf("unexpected error: %v", err)
	}
}
