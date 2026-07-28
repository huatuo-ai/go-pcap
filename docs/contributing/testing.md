# Testing

The project uses several layers of verification. A compiler change should exercise the narrowest relevant layer first and then the broader matrix that covers its packet-layout and compatibility effects.

| Layer | Location | Purpose |
| --- | --- | --- |
| Unit and parser/compiler cases | package tests and `filter/compile_cases_test.go` | Validate parsed filters and instruction generation. |
| cBPF VM behavior | `filter/vm_behavior_test.go` | Check accept/reject results on crafted packets. |
| Protocol matrix | `filter/protocol_matrix_test.go` | Cover L2, L3, L4, IPv4, IPv6, and logical combinations. |
| tcpdump equivalence | `filter/tcpdump_equivalence_test.go` | Compare decisions with checked-in tcpdump 4.99.0 / libpcap 1.10.0 programs. |
| Live integration | [`test/`](../../test/README.md) | Capture real loopback traffic through kernel and privilege paths. |

## Everyday commands

```sh
go build ./...
go vet ./...
make test
make fmt-check
make lint
make bench
```

`make test` runs Go unit tests, executable examples, VM behavior tests, RAW/L2 boundary tests, and the checked-in tcpdump decision-equivalence suite. `make bench` measures parser, compiler, `Size`, and VM match/miss behavior ten times with allocation reporting. Compare benchmark results only on equivalent machines and Go versions.

## Golden fixtures

The tcpdump programs live under [`filter/testdata/tcpdump-4.99.0-libpcap-1.10.0/`](../../filter/testdata/tcpdump-4.99.0-libpcap-1.10.0/). They are embedded by the filter package, so do not move them. The suite checks the accept/reject decision, not byte-for-byte instruction identity.

Deliberately refresh a fixture with `tcpdump -y <DLT> -ddd <expression>`, or with `tcpdump -ddd -r <pcap> <expression>` when a savefile with the right data-link type is available. Review the semantic change and update the fixture version note. Do not refresh goldens as an incidental part of another compiler edit. See the [fixture README](../../filter/testdata/tcpdump-4.99.0-libpcap-1.10.0/README.md) for the exact provenance rules.

## Live integration suite

The scripts in [`test/`](../../test/README.md) are Linux loopback capture tests for L2/L3/L4 filters. They need root or `CAP_NET_RAW`; unprivileged invocations print `SKIP` and exit successfully.

```sh
make integration
sudo -E env "PATH=$PATH" bash test/run.sh
```

Use the second command when you need to run the cases. Environment controls for timeouts, retries, and temporary artifacts are documented in `test/env.sh`.
