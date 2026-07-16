# Architecture

`go-pcap` separates packet acquisition from filter compilation. The public
surface is deliberately small: applications open a capture handle, attach a
compiled cBPF program, and consume packet data directly or through gopacket.

## Package map

| Area | Responsibility |
| --- | --- |
| root `pcap` package | Opens and manages live capture handles, installs raw or text filters, and exposes gopacket-compatible packet data. |
| `filter` package | Parses the supported tcpdump-style syntax, compiles it to cBPF, and provides EN10MB/RAW layout selection. |
| `cmd` package | Builds the `pcap` diagnostic CLI and formats tcpdump-style summaries. |

Platform-specific handle implementations live in `pcap_linux.go` and
`pcap_darwinbsd.go`. The public `OpenLive` entry point selects the appropriate
implementation at build time.

## Capture to cBPF flow

```text
expression
    │
    ▼
filter.Compile(expr, link type)
    │  parse → filter AST → labelled cBPF instructions
    ▼
bpf.Assemble
    │
    ▼
Handle.SetRawBPFFilter
    │
    ▼
kernel capture socket → Handle.ReadPacketData → gopacket / application
```

`Handle.SetBPFFilter` follows the same path for a live Ethernet capture. It
uses `filter.LinkTypeEthernet` because packets from an Ethernet capture handle
include the Ethernet header. Callers that supply raw L3 bytes should call
`filter.Compile` themselves with `filter.LinkTypeRaw`.

## Packet layout is part of the contract

The compiler does not infer whether byte zero is an Ethernet header or an IP
header. That choice changes every offset and determines whether L2 primitives
are meaningful. RAW compilation rejects a wholly L2-only rule with
`ErrL2OnlyLinkType` rather than silently returning a misleading program.

This is particularly useful in L3-only downstream paths, including loopback,
raw IP inputs, and kernel instrumentation points that observe an skb after its
MAC header is absent. A consumer with both L2 and L3 contexts should compile
for each layout and route packets according to their actual starting offset.

## Platform and privilege boundary

The library remains CGO-free. Linux capture normally uses an AF_PACKET
TPACKET_V3 mmap ring; a syscall path is available for older or constrained
environments. macOS/Darwin uses its native BPF interface. In either case,
packet capture needs the permissions granted by the operating system.

Compilation and cBPF VM tests are independent of capture privileges. This
allows the parser and compiler to be validated in ordinary development and CI
environments while the small live-capture suite runs only where loopback
capture privileges are available.

Read [Compiler internals](compiler-internals.md) for the labelled assembler and
[live capture](../guides/live-capture.md) for application-facing usage.
