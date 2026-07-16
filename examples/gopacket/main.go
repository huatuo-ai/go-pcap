// Copyright 2026 The HuaTuo Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	pcap "github.com/huatuo-ai/go-pcap"
)

const (
	defaultPacketCount = 5
	defaultSnaplen     = 1600
)

func main() {
	interfaceName := flag.String("i", "lo", "capture interface")
	packetCount := flag.Int("c", defaultPacketCount, "number of packets to print")
	expression := flag.String("filter", "ip", "tcpdump-style filter expression")
	flag.Parse()

	if *packetCount <= 0 {
		log.Fatal("-c must be greater than zero")
	}

	handle, err := pcap.OpenLive(
		context.Background(),
		*interfaceName,
		defaultSnaplen,
		true,
		time.Second,
		pcap.DefaultSyscalls,
	)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(*expression); err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, layers.LinkType(handle.LinkType()))
	for range *packetCount {
		packet, err := packetSource.NextPacket()
		if err != nil {
			log.Fatal(err)
		}
		printSummary(packet)
	}
}

func printSummary(packet gopacket.Packet) {
	fmt.Printf(
		"L2=%s L3=%s L4=%s\n",
		layerName(packet.Layer(layers.LayerTypeEthernet)),
		layerName(packet.NetworkLayer()),
		layerName(packet.TransportLayer()),
	)

	if networkLayer := packet.NetworkLayer(); networkLayer != nil {
		flow := networkLayer.NetworkFlow()
		fmt.Printf("  network: %s -> %s\n", flow.Src(), flow.Dst())
	}
}

func layerName(layer gopacket.Layer) string {
	if layer == nil {
		return "<none>"
	}

	return layer.LayerType().String()
}
