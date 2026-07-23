# Getting started

## Install

Add the module to a Go 1.23+ project:

```sh
go get github.com/huatuo-ai/go-pcap@latest
```

The library is written in Go and does not require CGO. Live capture is
available on Linux and macOS/Darwin; building a program does not itself require
capture privileges.

## Compile a filter

Choose the packet layout before compiling. Ethernet capture uses
`filter.LinkTypeEthernet`; packets that begin directly with an IPv4 or IPv6
header use `filter.LinkTypeRaw`.

```go
package main

import (
	"errors"
	"fmt"
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
	fmt.Println(len(raw))

	_, err = filter.Compile("arp", filter.LinkTypeRaw)
	if errors.Is(err, filter.ErrL2OnlyLinkType) {
		// ARP needs Ethernet framing; choose an Ethernet layout or reject it.
	}
}
```

`filter.Size(expr, linkType)` reports the number of cBPF instructions that a
successful `filter.Compile` call produces. See [Ethernet and RAW link
types](guides/linktype-raw.md) before compiling filters for loopback or custom
L3 inputs.

TCP flag filters use tcpdump/libpcap names. For example, a SYN+ACK filter is:

```text
tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)
```

## Capture packets

For a live interface, call `pcap.OpenLive`, apply a tcpdump-style filter with
`SetBPFFilter`, then use the resulting handle directly or with gopacket. Live
capture needs operating-system permission such as root or `CAP_NET_RAW` on
Linux.

```sh
sudo go run ./examples/gopacket -i lo -c 3
```

The repository includes more runnable programs in
[`examples/`](../examples/README.md). Continue with the [live capture
guide](guides/live-capture.md) for the complete API flow.
