# Filter language

The compiler accepts a useful tcpdump-style subset. It is intended for common
capture and packet-processing filters, not complete libpcap grammar
compatibility.

## Common expressions

```text
tcp and port 443
src portrange 1000-2000
ip6 and udp and port 53
src and dst host 192.0.2.1
ip multicast
tcp[tcpflags] == tcp-syn
tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)
vlan 100 and tcp port 443
mpls 100 and ip
tcp and port 80 or udp
not (tcp or udp)
```

Supported protocol and qualifier families include IPv4, IPv6, ARP/RARP, TCP,
UDP, SCTP, STP, ICMP, ICMP6, IGMP, PIM, ESP, AH, VRRP, host, network, port,
port ranges, multicast, VLAN/QinQ, MPLS, packet-byte arithmetic, `len`, and
common logical combinations. Host names are resolved once per compilation and
all returned A and AAAA addresses participate in the match.

Packet access uses network byte order and supports widths 1, 2, and 4:

```text
ether[12:2] == 0x0800
ip[0] & 0x0f > 5
tcp[tcpflags] == tcp-syn
tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)
len >= 128
```

Every generated packet-arithmetic access has a length guard. A truncated packet
therefore rejects instead of supplying a zero value to the comparison.

TCP flag constants use the tcpdump/libpcap names `tcp-syn`, `tcp-ack`,
`tcp-rst`, and so on. To match packets where both SYN and ACK are set, mask the
flags field first and compare the masked value to the same mask:

```text
tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)
```

This still matches packets with additional flags set, such as SYN+ACK+ECE. Use
`tcp[tcpflags] == (tcp-syn|tcp-ack)` when the flags field must be exactly
SYN+ACK.

Use `CompileWithOptions` when hostname resolution must be deterministic or
isolated in tests:

```go
insns, err := filter.CompileWithOptions(expr, filter.CompileOptions{
	LinkType: filter.LinkTypeRaw,
	Resolver: resolver,
})
```

`Resolver` is the one-method `LookupHost(context.Context, string)` interface.
`Compile` remains the compatible convenience entry point and uses the default
network resolver.

## Logical operators

`and` binds tighter than `or`. The following expression is read as
`(tcp and port 80) or udp`:

```text
tcp and port 80 or udp
```

Use parentheses whenever the intended grouping is not obvious, especially
around negation:

```text
not (tcp or udp)
```

## Current boundaries

The following tcpdump features are not implemented and fail with
`ErrUnsupportedFeature` when recognized:

- protocol-number literals;
- `protochain` and IPv6 extension-header traversal;
- `broadcast` predicates that require an interface netmask;
- `inbound`, `outbound`, and `ifindex` metadata predicates;
- non-EN10MB/RAW data-link layouts; and
- the rest of the full tcpdump/libpcap grammar.

An expression can be syntactically accepted yet invalid because a hostname,
port, address, or qualifier is unsupported. Check errors with `errors.Is`:

```go
insns, err := filter.Compile(expr, filter.LinkTypeEthernet)
if errors.Is(err, filter.ErrEmptyFilter) {
	// Ask the caller to provide a filter.
} else if errors.Is(err, filter.ErrUnsupportedFeature) {
	// Report the recognized feature that is not implemented.
} else if errors.Is(err, filter.ErrHostResolution) {
	// Report that the host name had no usable A/AAAA records.
} else if errors.Is(err, filter.ErrInvalidFilter) {
	// Report the malformed expression.
}
```

The [error-handling example](../../examples/error-handling/main.go) shows the
public sentinel errors. Link layout also changes what a valid filter can mean;
read [Ethernet and RAW link types](linktype-raw.md) before using the compiler
away from a regular Ethernet capture interface.
