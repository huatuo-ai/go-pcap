# Examples

Each example is an independent program in the main module.

| Example | Purpose | Run |
| --- | --- | --- |
| `filter-compile` | Compile Ethernet and RAW filters to cBPF instructions. | `go run ./examples/filter-compile` |
| `error-handling` | Dispatch filter compiler sentinel errors with `errors.Is`. | `go run ./examples/error-handling` |
| `gopacket` | Capture packets, apply a filter, and print decoded L2/L3/L4 summaries. | `sudo go run ./examples/gopacket -i lo -c 3` |

The `filter-compile` example includes a TCP SYN+ACK flag expression:
`tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)`. The first two
examples do not require capture privileges. `gopacket` opens a live capture
device and needs root or `CAP_NET_RAW`; running the `go run` command through
`sudo` is the simplest option. For a long-lived compiled binary, grant only the
needed capability with `setcap` according to your platform's security policy.
