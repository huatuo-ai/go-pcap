# Live capture

`OpenLive` creates a `Handle` for a network interface. A handle implements the
gopacket packet-data-source interface, so it can be passed directly to
`gopacket.NewPacketSource`.

## Open a handle

```go
handle, err := pcap.OpenLive(
	context.Background(),
	"eth0",
	1600,
	true,
	time.Second,
	pcap.DefaultSyscalls,
)
if err != nil {
	return err
}
defer handle.Close()
```

The arguments are, in order: a cancellation context, device name, snapshot
length, promiscuous-mode setting, read timeout, and whether to force the
syscall capture path. On Linux, the default path uses an AF_PACKET TPACKET_V3
mmap ring. `--syscalls` in the CLI selects the fallback path for older kernels
or constrained environments; it does not bypass capture permissions.

Use a context that belongs to the lifetime of the capture and always close the
handle when finished.

## Apply a filter

`SetBPFFilter` compiles the expression for Ethernet framing before attaching it
to the handle:

```go
if err := handle.SetBPFFilter("tcp and port 443"); err != nil {
	return err
}
```

Live Ethernet interfaces should use this method rather than compiling a RAW
program manually. For byte streams that begin at an IP header, use the
package-level compiler described in [Ethernet and RAW link
types](linktype-raw.md).

## Decode with gopacket

```go
source := gopacket.NewPacketSource(handle, layers.LinkType(handle.LinkType()))
for packet := range source.Packets() {
	if networkLayer := packet.NetworkLayer(); networkLayer != nil {
		flow := networkLayer.NetworkFlow()
		fmt.Printf("%s -> %s\n", flow.Src(), flow.Dst())
	}
}
```

For a bounded command, call `NextPacket` a fixed number of times instead. The
[gopacket example](../../examples/gopacket/main.go) accepts `-i` and `-c` and
prints an L2/L3/L4 summary.

## Permissions and platforms

Live capture is supported on Linux and macOS/Darwin. It commonly requires root
or an operating-system capability. On Linux, grant and scope `CAP_NET_RAW`
according to the deployment's security policy, or run the capture process with
the necessary privilege. A program can compile filters without any special
permission.

For local loopback validation, see the [integration test guide](../contributing/testing.md).
