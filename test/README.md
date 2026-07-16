# Integration tests

Go unit tests do not live in this directory. Run all of those with:

```sh
go test ./...
```

This directory contains the repository's loopback live-capture integration
tests. They exercise L2, L3, and L4 filters against real IPv4 and IPv6
loopback traffic. End-to-end tests belong to applications that consume this
library, not to this library repository.

Packet capture requires `CAP_NET_RAW` (or root). An unprivileged invocation
prints `SKIP` and exits successfully, so it is safe to run locally:

```sh
make integration
```

To execute the cases, build the CLI and run the suite with capture privileges:

```sh
make build
sudo -E env "PATH=$PATH" bash test/run.sh
```

`env.sh` documents the available environment variables, including the capture
timeout, startup delay, retry budget, and temporary-directory location.

## tcpdump golden fixtures

The tcpdump decision-equivalence fixtures intentionally remain in
[`filter/testdata/tcpdump-4.99.0-libpcap-1.10.0/`](../filter/testdata/tcpdump-4.99.0-libpcap-1.10.0/).
They are generated from tcpdump 4.99.0 / libpcap 1.10.0 `-ddd` output. The
filter package embeds them with `go:embed`, so moving them outside the package
would prevent self-contained test binaries.

For fixture provenance and the deliberate regeneration process, see the
[fixture README](../filter/testdata/tcpdump-4.99.0-libpcap-1.10.0/README.md).
