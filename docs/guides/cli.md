# CLI guide

The repository includes `pcap`, a live-capture utility that prints tcpdump-style packet summaries. It is a convenient diagnostic program, not a complete replacement for tcpdump or a pcap-file reader.

## Build and run

```sh
make build
./pcap --help
./pcap -nn -i eth0 -c 10 'tcp port 443'
./pcap -nn -i eth0 -c 10 'tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)'
```

Use `-nn` in scripts to keep host and service names numeric and therefore make output deterministic. Quote flag expressions in the shell because `&`, `|`, and parentheses are shell metacharacters. Common switches compatible with tcpdump 4.99.x are:

```text
-i  -c  -n/-nn  -q  -v  -e  -X  -A  -s  -p
```

The CLI decodes common Ethernet, ARP, IPv4, IPv6, TCP, UDP, and ICMP traffic. It only captures live traffic: pcap file read/write modes and less common tcpdump switches are not implemented.

Packet capture usually needs operating-system permission. On Linux, run with the appropriate capability or privilege. `--syscalls` bypasses the default TPACKET_V3 mmap ring when the kernel or container cannot use it, but does not remove the permission requirement.

## Cross-compile

Set `OS` and `ARCH` when building a target:

```sh
make build OS=linux ARCH=arm64
make build OS=linux ARCH=arm GOARM=6
make build OS=linux ARCH=arm GOARM=7
```

The first native build writes `./pcap`. Cross-target artifacts include their target suffix; set `BINDIR` to select a different output directory. ARMv6 and ARMv7 are distinct ABI targets: do not deploy an ARMv7 binary to an ARMv6 device. The release matrix does not publish a soft-float ARM artifact.
