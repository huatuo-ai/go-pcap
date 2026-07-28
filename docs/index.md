# go-pcap

`go-pcap` is a native Go packet-capture library and tcpdump-style classic BPF (cBPF) filter compiler. It offers a libpcap-like capture surface without CGO, so static builds and cross-compilation remain straightforward.

The project is derived from [packetcap/go-pcap](https://github.com/packetcap/go-pcap). HuaTuo's maintained fork adds an L3-aware compiler that can target either Ethernet packets or packets beginning at an IP header, a two-pass label-based assembler, and decision-oriented compatibility tests.

The filter language is a practical tcpdump-style subset, not a claim of full libpcap grammar compatibility.

## Documentation

- [Getting started](getting-started.md) installs the module and compiles a first filter.
- [Live capture](guides/live-capture.md) explains `OpenLive`, privileges, and gopacket integration.
- [Filter language](guides/filter-language.md) describes the supported syntax and its boundaries.
- [Ethernet and RAW link types](guides/linktype-raw.md) explains how packet layout changes filter meaning.
- [CLI guide](guides/cli.md) covers the bundled tcpdump-style capture utility.
- [Architecture](concepts/architecture.md) and [compiler internals](concepts/compiler-internals.md) describe the library's implementation and verification model.
- [Contributing](contributing/index.md) links to development, test, and release guidance.

Documentation is written in English first. Future Chinese pages should mirror each English path under `docs/zh/` (for example, `docs/zh/guides/live-capture.md`), which is compatible with `mkdocs-static-i18n` when a documentation site is introduced.
