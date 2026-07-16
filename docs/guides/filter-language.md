# Filter language

The compiler accepts a useful tcpdump-style subset. It is intended for common
capture and packet-processing filters, not complete libpcap grammar
compatibility.

## Common expressions

```text
tcp and port 443
ip6 and udp and port 53
src and dst host 192.0.2.1
ip multicast
tcp and port 80 or udp
not (tcp or udp)
```

Supported protocol and qualifier families include IPv4, IPv6, ARP/RARP, TCP,
UDP, ICMP, ICMP6, IGMP, PIM, ESP, AH, VRRP, host, network, port, multicast,
and common logical combinations.

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

The following tcpdump features are not implemented:

- byte-offset predicates;
- protocol-number literals;
- port ranges;
- VLAN and MPLS encapsulation; and
- the rest of the full tcpdump/libpcap grammar.

An expression can be syntactically accepted yet invalid because a hostname,
port, address, or qualifier is unsupported. Check errors with `errors.Is`:

```go
insns, err := filter.Compile(expr, filter.LinkTypeEthernet)
if errors.Is(err, filter.ErrEmptyFilter) {
	// Ask the caller to provide a filter.
} else if errors.Is(err, filter.ErrInvalidFilter) {
	// Report the malformed or unsupported expression.
}
```

The [error-handling example](../../examples/error-handling/main.go) shows all
four public sentinel errors. Link layout also changes what a valid filter can
mean; read [Ethernet and RAW link types](linktype-raw.md) before using the
compiler away from a regular Ethernet capture interface.
