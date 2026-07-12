# go-pcap

[简体中文](README_CN.md)

`go-pcap` is a native Go packet-capture library and tcpdump-style cBPF filter
compiler. It provides a libpcap-like capture surface without CGO, making
`CGO_ENABLED=0` builds and cross-compilation straightforward.

## Why this fork

This project is derived from
[packetcap/go-pcap](https://github.com/packetcap/go-pcap) and remains licensed
under Apache-2.0. The filter compiler has been substantially reworked by the
HuaTuo team while retaining the pure-Go design:

- Compile the same filter AST for Ethernet (`EN10MB`) or raw IP (`RAW`, L3)
  packet layouts.
- Use a two-pass, label-based cBPF assembler instead of hand-calculated jump
  offsets.
- Correct `and`/`or` precedence, parenthesized negation, composite
  short-circuiting, and several L2/L3 edge cases.
- Support IPv4, IPv6, ARP/RARP, TCP, UDP, ICMP, ICMP6, IGMP, PIM, ESP, AH,
  VRRP, host, network, port, multicast, and common logical combinations.
- Provide executable Examples, VM behavior tests, tcpdump decision-equivalence
  checks when tcpdump is installed, and repeatable benchmarks.

The implemented filter language is a useful tcpdump-style subset, not a claim
of complete libpcap grammar compatibility.

## Install

```sh
go get github.com/huatuo-ai/go-pcap@latest
```

## Live capture

`Handle` is compatible with the `gopacket` packet-source interfaces. Live
capture filters are compiled for Ethernet framing.

```go
package main

import (
	"context"
	"log"
	"time"

	pcap "github.com/huatuo-ai/go-pcap"
)

func main() {
	h, err := pcap.OpenLive(
		context.Background(),
		"eth0",
		1600,
		true,
		time.Second,
		pcap.DefaultSyscalls,
	)
	if err != nil {
		log.Fatal(err)
	}
	defer h.Close()

	if err := h.SetBPFFilter("tcp and port 443"); err != nil {
		log.Fatal(err)
	}

	data, captureInfo, err := h.ReadPacketData()
	_ = data
	_ = captureInfo
	_ = err
}
```

## Compile filters for Ethernet or raw IP

Use the package-level compiler when the input packet layout is known. Do not
cast a pcap/link-layer numeric value to `filter.LinkType`: choose the semantic
layout explicitly.

```go
package main

import (
	"errors"
	"log"

	"github.com/huatuo-ai/go-pcap/filter"
	"golang.org/x/net/bpf"
)

func main() {
	insns, err := filter.Compile("ip6 and udp and port 53", filter.LinkTypeRaw)
	if err != nil {
		log.Fatal(err)
	}

	raw, err := bpf.Assemble(insns)
	if err != nil {
		log.Fatal(err)
	}
	_ = raw

	_, err = filter.Compile("arp", filter.LinkTypeRaw)
	if errors.Is(err, filter.ErrL2OnlyLinkType) {
		// Choose Ethernet framing, or reject the L2-only expression.
	}
}
```

`filter.Size(expr, linkType)` returns the number of cBPF instructions that
`filter.Compile` would emit.

## Link-type behavior and errors

| Layout | Packet starts at | Supported predicates |
| --- | --- | --- |
| `filter.LinkTypeEthernet` | Ethernet header | L2 and L3 predicates |
| `filter.LinkTypeRaw` | IPv4/IPv6 header | L3 predicates only |

On `RAW`, expressions that are entirely L2-only, such as `arp`, `rarp`, or
`ether host aa:bb:cc:dd:ee:ff`, return `ErrL2OnlyLinkType` rather than silently
producing a filter with the wrong meaning. Empty expressions return
`ErrEmptyFilter`; unsupported layouts return `ErrUnsupportedLinkType`.

## Filter language

Common supported expressions include:

```text
tcp and port 443
ip6 and udp and port 53
src and dst host 192.0.2.1
ip multicast
tcp and port 80 or udp
not (tcp or udp)
```

`and` binds tighter than `or`; use parentheses when explicit grouping makes a
rule easier to read. Byte-offset predicates, protocol-number literals, port
ranges, VLAN/MPLS encapsulation, and the full tcpdump grammar are not currently
implemented.

## Reliability: tests and benchmarks

Run the full test suite with:

```sh
make test
```

It runs unit tests, Go Examples, cBPF VM behavior tests, RAW/L2 boundary tests,
and a tcpdump/libpcap decision-equivalence suite when `tcpdump` is available.
The equivalence suite compares packet accept/reject decisions, not instruction
bytes, because libpcap optimization output can vary by version.

Run repeatable filter benchmarks with:

```sh
make bench
```

This executes parser, compiler, size, and VM match/miss benchmarks ten times
with `-benchmem`, reporting `ns/op`, `B/op`, and `allocs/op`. Compare benchmark
results only on equivalent machines and Go versions.

## CLI

Build the sample capture utility:

```sh
make build
./pcap --help
```

Cross-compilation is supported through the existing `OS` and `ARCH` Makefile
variables. Build artifacts are written under `dist/`.

## Platform support and limitations

Capture support is available for Linux and macOS/Darwin. Packet capture usually
requires the appropriate operating-system privileges. `RAW` is a compiler
layout for packets beginning at an IP header; it is not a substitute for an
Ethernet capture handle and cannot evaluate L2-only predicates.

## Contributing

Issues and pull requests are welcome, especially for new protocol support,
link types, compatibility cases, and performance work. Please run `make test`
and the relevant `make bench` cases before submitting a change.

## Acknowledgments and license

The original capture library is derived from
[packetcap/go-pcap](https://github.com/packetcap/go-pcap). The L3-aware filter
compiler, label assembler, and reliability work were developed by the HuaTuo
team. See [LICENSE](LICENSE) for the Apache-2.0 license text.
