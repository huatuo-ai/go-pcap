# Ethernet and RAW link types

The compiler needs the packet layout, not merely a numeric pcap data-link
value. Select one of the two semantic layouts explicitly:

| Layout | Packet starts at | Supported predicates |
| --- | --- | --- |
| `filter.LinkTypeEthernet` | Ethernet header | L2 and L3 predicates |
| `filter.LinkTypeRaw` | IPv4 or IPv6 header | L3 predicates only |

Do not cast an external pcap/link-layer number to `filter.LinkType`. Instead,
choose the layout that describes the first byte supplied to the cBPF program.

```go
ethernet, err := filter.Compile("tcp and port 443", filter.LinkTypeEthernet)
raw, err := filter.Compile("tcp and port 443", filter.LinkTypeRaw)
```

The same expression produces different instruction offsets because Ethernet
has an L2 header and RAW does not.

## L2-only filters on RAW

`arp`, `rarp`, and `ether host` require Ethernet framing. When the complete
expression is L2-only and the selected layout is RAW, the compiler returns
`ErrL2OnlyLinkType` instead of emitting a filter with the wrong meaning:

```go
_, err := filter.Compile("arp", filter.LinkTypeRaw)
if errors.Is(err, filter.ErrL2OnlyLinkType) {
	// Compile for Ethernet, or reject this rule for an L3-only path.
}
```

This distinction matters for loopback interfaces, raw IP packet streams, and
kernel paths where the Ethernet header is no longer present. RAW is a compiler
layout; it is not an Ethernet capture handle replacement.

## Other compiler errors

- `ErrEmptyFilter`: the expression is empty.
- `ErrInvalidFilter`: the expression cannot be compiled by the supported
  grammar and validation rules.
- `ErrUnsupportedFeature`: the expression names a recognized feature that is
  not implemented for this compiler context.
- `ErrHostResolution`: a hostname lookup failed or returned no usable address.
- `ErrUnsupportedLinkType`: the requested layout is not Ethernet or RAW.
- `ErrL2OnlyLinkType`: the selected RAW layout cannot evaluate an entirely
  L2-only expression.

See [Getting started](../getting-started.md) or run
[`examples/filter-compile`](../../examples/filter-compile/main.go) for a
complete EN10MB/RAW comparison and cBPF assembly step.
