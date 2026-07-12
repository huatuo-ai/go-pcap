# tcpdump cBPF golden references

These files are the raw decimal output of `tcpdump -ddd`, generated with:

```text
tcpdump version 4.99.0
libpcap version 1.10.0
```

Each file records one expression and data-link type.  The tests compare the
accept/reject decisions of the resulting reference program with the program
compiled by this package; they intentionally do not require byte-for-byte
instruction equality.

To deliberately refresh a reference, run the command named by the test case,
review the semantic change, and update both the fixture and this version note.
Do not refresh these files as part of an unrelated compiler change.
