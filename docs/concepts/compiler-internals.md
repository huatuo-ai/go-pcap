# Compiler internals

The filter compiler converts the supported tcpdump-style expression language into classic BPF instructions. Its design prioritizes a semantically correct accept/reject decision over reproducing tcpdump's exact instruction sequence.

## From expression to program

1. The legacy lexer and the extended arithmetic lexer parse the expression into primitive, arithmetic-comparison, and composite filters.
2. Logical filters are distilled with tcpdump precedence: `and` binds more tightly than `or`; parentheses and negation remain explicit in the tree.
3. A filter emits a labelled control-flow program for the selected link layout.
4. The program finalizer resolves forward labels into cBPF jump skips and returns the instruction list.
5. `golang.org/x/net/bpf.Assemble` converts the typed instructions to raw cBPF instructions before a capture handle installs them.

The `filter` package owns this flow. Layout implementations supply the L2/L3 offsets and the instructions used to recognize IPv4 or IPv6 packets.

## Stateful packet cursors

VLAN and MPLS change the location and interpretation of the next header. The extended compiler therefore carries an immutable packet cursor down each AST branch. An `and` continuation receives the cursor advanced by a successful transition, while each `or` alternative starts with the cursor that entered the branch. Negation also restores its input cursor. This preserves short-circuit semantics for expressions such as:

```text
(vlan and tcp port 80) or tcp port 443
vlan and vlan and ip[0] & 0x0f > 5
mpls and mpls and ip6
```

MPLS transitions verify the bottom-of-stack bit before exposing an inner IPv4/IPv6 header. Arithmetic packet loads use explicit length checks and cBPF scratch registers for nested expressions.

## Two-pass labelled assembly

Classic BPF jump instructions use relative skip counts. Calculating those counts directly while recursively emitting `and`, `or`, and `not` expressions is fragile: adding one instruction can invalidate multiple hand-calculated offsets.

Instead, the compiler emits symbolic labels such as the common accept and reject destinations. Each conditional branch initially refers to a true and a false label. Finalization records the position of every bound label and then calculates the forward skips. It rejects unbound labels, backward jumps, skip overflow, and attempts to finalize twice.

This separates control-flow intent from bytecode layout. Complex short-circuit expressions can be read and tested as branches rather than as arithmetic on jump offsets.

## Link layouts

`ethernetLayout` starts L3 offsets after the 14-byte Ethernet header and can evaluate L2 protocols. `rawLayout` starts at byte zero, probes the IP version nibble, and has no L2 protocol support. VLAN advances the Ethernet EtherType and L3 offsets by four bytes per tag. MPLS advances by four bytes per label and then probes the inner IP version. A RAW program maps L2-only protocol checks to a non-match; when the whole expression reduces to a reject-all program, the public compiler returns `ErrL2OnlyLinkType`.

The public `LinkType` enum is intentionally semantic and closed. The compiler does not assume that arbitrary pcap data-link numbers share the same byte layout.

## Verify decisions, not instruction identity

Different cBPF generators may optimize equivalent expressions into different instruction lists. Tests therefore use several complementary signals:

- parser and compiler cases for AST and emitted-program behavior;
- cBPF VM tests for accept/reject behavior on crafted packets;
- protocol matrices for IPv4, IPv6, L2, L3, and L4 combinations;
- tcpdump 4.99.0 / libpcap 1.10.0 golden programs, compared by decision rather than instruction bytes; and
- loopback live-capture tests for real kernel and permission paths.

This "decide correctly" philosophy makes the code resilient to valid optimization changes while retaining a compatibility reference. See the [testing guide](../contributing/testing.md) before changing a primitive or refreshing a golden fixture.
