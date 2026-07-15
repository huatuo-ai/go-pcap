package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/huatuo-ai/go-pcap"
)

const defaultSnaplen = 262144

var (
	useGopacket bool
	useSyscalls bool
	debug       bool
	iface       string
	timeout     time.Duration
	snaplen     int
	packetCount int
	numeric     int
	verbosity   int
	quiet       bool
	linkLayer   bool
	hexDump     bool
	asciiDump   bool
	noPromisc   bool
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "pcap [expression]",
	Short: "Capture packets with tcpdump-compatible text output",
	Long: "Capture packets with tcpdump-compatible text output. " +
		"The optional expression uses the supported tcpdump-style cBPF filter syntax.",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if snaplen <= 0 {
			return fmt.Errorf("snapshot length must be greater than zero")
		}
		if packetCount < 0 {
			return fmt.Errorf("packet count must not be negative")
		}

		if debug {
			log.SetLevel(log.DebugLevel)
		}
		if useGopacket {
			log.Debug("--gopacket is retained for compatibility; packet decoding is always performed by gopacket")
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		handle, err := pcap.OpenLive(ctx, iface, int32(snaplen), !noPromisc, timeout, useSyscalls)
		if err != nil {
			return err
		}
		defer handle.Close()

		filter := strings.Join(args, " ")
		if err := handle.SetBPFFilter(filter); err != nil {
			return fmt.Errorf("set filter %q: %w", filter, err)
		}

		device := iface
		if device == "" {
			device = "any"
		}
		fmt.Fprintf(
			cmd.ErrOrStderr(),
			"tcpdump: listening on %s, link-type EN10MB (Ethernet), snapshot length %d bytes\n",
			device,
			snaplen,
		)

		printer := newTCPDumpPrinter(tcpdumpOptions{
			numeric:   numeric,
			quiet:     quiet,
			verbosity: verbosity,
			linkLayer: linkLayer,
			hexDump:   hexDump,
			asciiDump: asciiDump,
		})

		for captured := 0; ; {
			data, captureInfo, err := handle.ReadPacketData()
			if err != nil {
				return err
			}
			if len(data) == 0 {
				continue
			}

			packet := gopacket.NewPacket(data, layers.LinkType(handle.LinkType()), gopacket.Default)
			packet.Metadata().CaptureInfo = captureInfo
			fmt.Fprintln(cmd.OutOrStdout(), printer.format(packet))

			captured++
			if packetCount > 0 && captured >= packetCount {
				return nil
			}
		}
	},
}

func init() {
	rootCmd.Flags().BoolVar(
		&useGopacket,
		"gopacket",
		false,
		"deprecated compatibility flag; packets are always decoded with gopacket",
	)
	rootCmd.Flags().BoolVar(
		&useSyscalls,
		"syscalls",
		pcap.DefaultSyscalls,
		"use syscalls instead of mmap when mmap is available; the default varies by platform",
	)
	rootCmd.Flags().BoolVar(&debug, "debug", false, "print internal debugging messages")
	rootCmd.Flags().StringVarP(&iface, "interface", "i", "", "listen on interface")
	rootCmd.Flags().DurationVar(&timeout, "timeout", 0, "stop capture after a duration, for example 10s or 1m")
	rootCmd.Flags().IntVarP(&packetCount, "count", "c", 0, "exit after receiving count packets")
	rootCmd.Flags().CountVarP(&numeric, "numeric", "n", "do not resolve host names; use -nn to keep ports numeric too")
	rootCmd.Flags().CountVarP(&verbosity, "verbose", "v", "print detailed packet headers")
	rootCmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "print less protocol information")
	rootCmd.Flags().BoolVarP(&linkLayer, "link", "e", false, "print the link-layer header")
	rootCmd.Flags().BoolVarP(&hexDump, "hex", "X", false, "print packet data in hex and ASCII")
	rootCmd.Flags().BoolVarP(&asciiDump, "ascii", "A", false, "print packet data as ASCII")
	rootCmd.Flags().IntVarP(&snaplen, "snapshot-length", "s", defaultSnaplen, "snapshot length in bytes")
	rootCmd.Flags().BoolVarP(
		&noPromisc,
		"no-promiscuous-mode",
		"p",
		false,
		"do not put the interface into promiscuous mode",
	)
}
