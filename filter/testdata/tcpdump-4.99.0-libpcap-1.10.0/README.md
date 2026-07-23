# tcpdump cBPF golden references

These files are the raw decimal output of `tcpdump -ddd`, generated with:

```text
tcpdump version 4.99.0
libpcap version 1.10.0
```

`en10mb_tcp_syn_ack_flags.ddd` and the EN10MB VLAN/MPLS cursor fixtures were
generated with Apple tcpdump 4.99.1 and libpcap 1.10.1 from
`libpcap/tests/filter/loopback.pcap`; they stay in this directory because the
test compares accept/reject decisions rather than exact instruction identity.

Each file records one expression and data-link type. The fixture names map to
the expressions in `TestTCPDumpGoldenDecisionEquivalence`. The tests compare
the accept/reject decisions of the resulting reference program with the
program compiled by this package; they intentionally do not require
byte-for-byte instruction equality.

To deliberately refresh a reference, run `tcpdump -y <DLT> -ddd <expression>`
for the matching test case, or `tcpdump -ddd -r <pcap> <expression>` with a
savefile that has the matching data-link type. Review the semantic change and
update both the fixture and this version note. Do not refresh these files as
part of an unrelated compiler change.
