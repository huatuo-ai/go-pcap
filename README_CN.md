# go-pcap

[English](README.md)

`go-pcap` 是一个原生 Go 的抓包库和 tcpdump 风格 cBPF 过滤编译器。它不依赖
CGO，因此可以方便地使用 `CGO_ENABLED=0` 构建和交叉编译。

## 为什么维护这个分支

本项目基于 [packetcap/go-pcap](https://github.com/packetcap/go-pcap) 演进，继续
使用 Apache-2.0 许可证，并保留纯 Go 的设计。HuaTuo 团队在此基础上大幅重构了
过滤编译器：

- 同一份过滤 AST 可针对 Ethernet（`EN10MB`）和裸 IP（`RAW`、L3）报文布局编译。
- 用两阶段、基于标签的 cBPF 汇编器取代手工计算跳转偏移。
- 修复 `and`/`or` 优先级、括号否定、复合表达式短路和多种 L2/L3 边界问题。
- 支持 IPv4、IPv6、ARP/RARP、TCP、UDP、ICMP、ICMP6、IGMP、PIM、ESP、AH、
  VRRP、host、net、port、multicast 及常用逻辑组合。
- 提供可执行 Example、cBPF VM 行为测试、安装 tcpdump 时的判定等价测试，以及
  可重复运行的 benchmark。

这里实现的是一个实用的 tcpdump 风格语法子集，不宣称完整兼容 libpcap 的全部
语法。

## 安装

```sh
go get github.com/huatuo-ai/go-pcap@latest
```

## 实时抓包

`Handle` 与 `gopacket` 的 packet source 接口兼容。实时抓包时的过滤规则按照
Ethernet 帧布局编译。

```go
package main

import (
	"context"
	"log"
	"time"

	pcap "github.com/huatuo-ai/go-pcap"
)

func main() {
	h, err := pcap.OpenLive(
		context.Background(),
		"eth0",
		1600,
		true,
		time.Second,
		pcap.DefaultSyscalls,
	)
	if err != nil {
		log.Fatal(err)
	}
	defer h.Close()

	if err := h.SetBPFFilter("tcp and port 443"); err != nil {
		log.Fatal(err)
	}

	data, captureInfo, err := h.ReadPacketData()
	_ = data
	_ = captureInfo
	_ = err
}
```

## 为 Ethernet 或裸 IP 编译过滤器

当调用方明确知道报文布局时，应使用包级编译入口。不要把 pcap 或链路层数值直接
强转成 `filter.LinkType`；应显式选择语义上的报文布局。

```go
package main

import (
	"errors"
	"log"

	"github.com/huatuo-ai/go-pcap/filter"
	"golang.org/x/net/bpf"
)

func main() {
	insns, err := filter.Compile("ip6 and udp and port 53", filter.LinkTypeRaw)
	if err != nil {
		log.Fatal(err)
	}

	raw, err := bpf.Assemble(insns)
	if err != nil {
		log.Fatal(err)
	}
	_ = raw

	_, err = filter.Compile("arp", filter.LinkTypeRaw)
	if errors.Is(err, filter.ErrL2OnlyLinkType) {
		// 应改用 Ethernet 布局，或拒绝这条只适用于二层的规则。
	}
}
```

`filter.Size(expr, linkType)` 返回 `filter.Compile` 对相同输入会生成的 cBPF
指令数量。

## 链路类型与错误语义

| 布局 | 报文起始位置 | 可用原语 |
| --- | --- | --- |
| `filter.LinkTypeEthernet` | Ethernet header | 二层和三层原语 |
| `filter.LinkTypeRaw` | IPv4/IPv6 header | 仅三层原语 |

在 `RAW` 布局中，完全由二层原语构成的表达式，例如 `arp`、`rarp` 或
`ether host aa:bb:cc:dd:ee:ff`，会返回 `ErrL2OnlyLinkType`，不会静默生成
语义错误的过滤器。空表达式返回 `ErrEmptyFilter`；不支持的布局返回
`ErrUnsupportedLinkType`。

## 过滤语法

常用的受支持表达式包括：

```text
tcp and port 443
ip6 and udp and port 53
src and dst host 192.0.2.1
ip multicast
tcp and port 80 or udp
not (tcp or udp)
```

`and` 的优先级高于 `or`；当规则较复杂时建议使用括号明确分组。当前不支持字节
偏移表达式、数字协议号字面量、端口范围、VLAN/MPLS 封装以及完整 tcpdump 语法。

## 可靠性：测试与基准

运行完整测试：

```sh
make test
```

该命令会运行单元测试、Go Example、cBPF VM 行为测试、RAW/L2 边界测试；若系统
安装了 `tcpdump`，还会运行与 tcpdump/libpcap 的逐报文判定等价测试。等价测试比较
报文的接受/拒绝结果，而不是逐条比较指令，因为不同 libpcap 版本的优化器可能产生
不同但等价的指令序列。

运行可重复的 filter benchmark：

```sh
make bench
```

该命令以 `-benchmem` 运行解析、编译、Size、VM match/miss 基准各十次，输出
`ns/op`、`B/op` 和 `allocs/op`。性能数据应只在相同机器和 Go 版本之间比较。

## CLI

构建示例抓包工具：

```sh
make build
./pcap --help
```

CLI 对常见的 Ethernet、ARP、IPv4、IPv6、TCP、UDP 和 ICMP 流量输出 tcpdump 风格
摘要。常用显示参数与 tcpdump 4.99.x 兼容：`-i`、`-c`、`-n`/`-nn`、`-q`、
`-v`、`-e`、`-X`、`-A`、`-s` 和 `-p`。脚本中建议使用 `-nn`，以保
持主机名和服务名均为数字形式，保证输出稳定。

```sh
./pcap -nn -i eth0 -c 10 'tcp port 443'
```

该 CLI 仅支持实时抓包；读取/写入 pcap 文件及较少使用的 tcpdump 参数暂未实现。

Makefile 支持通过 `OS` 和 `ARCH` 变量进行交叉编译。默认的主机可执行文件为项目根
目录下的 `./pcap`；目标特定产物也默认位于项目根目录，可通过 `BINDIR` 指定其他
目录。32 位 Linux ARM 必须显式选择 ABI 级别：

```sh
make build OS=linux ARCH=arm GOARM=6 # pcap-linux-armv6
make build OS=linux ARCH=arm GOARM=7 # pcap-linux-armv7
```

ARMv7 二进制不能部署到 ARMv6 设备。当前发布矩阵不提供 soft-float ARM 构建产物。

## 平台支持与限制

目前支持 Linux 和 macOS/Darwin 抓包。抓包通常需要操作系统授予相应权限。Linux
默认抓包路径使用 AF_PACKET 的 TPACKET_V3 mmap ring，因此还需要内核支持和
`CAP_NET_RAW`。对于较旧内核或受限容器，`./pcap --syscalls` 可以绕过
mmap/TPACKET_V3 路径，但不会取消抓包权限要求。`RAW` 是“报文从 IP header 开始”的
编译布局，不等同于 Ethernet 抓包句柄，也不能执行仅适用于二层的原语。

## 贡献

欢迎提交 issue 和 PR，尤其是新的协议、LinkType、兼容性用例和性能改进。提交前请
运行 `make test`，并在相关改动中运行 `make bench`。

## 致谢与许可证

原始抓包库来自 [packetcap/go-pcap](https://github.com/packetcap/go-pcap)。面向 L3 的
过滤编译器、标签汇编器和可靠性工作由 HuaTuo 团队完成。Apache-2.0 许可证文本见
[LICENSE](LICENSE)。
