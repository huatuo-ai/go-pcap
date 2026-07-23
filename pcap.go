package pcap

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"golang.org/x/net/bpf"
)

const (
	// DefaultSyscalls whether the default is to use syscalls or not
	DefaultSyscalls = defaultSyscalls
)

// Packet a single packet returned by a listen call
type Packet struct {
	B     []byte
	Info  gopacket.CaptureInfo
	Error error
}

// OpenLive open a live capture. Returns a Handle that implements https://godoc.org/github.com/gopacket/gopacket#PacketDataSource
// so you can pass it there.
// Use the context to cancel the capture after a timeout or other condition.
func OpenLive(ctx context.Context, device string, snaplen int32, promiscuous bool, timeout time.Duration, syscalls bool) (handle *Handle, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	handle, err = openLive(ctx, device, snaplen, promiscuous, timeout, syscalls)
	if err != nil {
		return nil, err
	}
	return handle, err
}

// Listen simple one-step command to listen and send packets over a returned channel
func (h *Handle) Listen() chan Packet {
	c := make(chan Packet, 50)
	go func() {
		for {
			b, ci, err := h.ReadPacketData()
			c <- Packet{
				B:     b,
				Info:  ci,
				Error: err,
			}
		}
	}()
	return c
}

// set a classic BPF filter on the listener. filter must be compliant with
// tcpdump syntax.
func (h *Handle) SetBPFFilter(expr string) error {
	expr2 := strings.TrimSpace(expr)
	// empty strings are not of interest
	if expr2 == "" {
		return nil
	}
	instructions, err := compileLiveFilter(expr2)
	if err != nil {
		return fmt.Errorf("compile filter into instructions: %w", err)
	}
	raw, err := bpf.Assemble(instructions)
	if err != nil {
		return fmt.Errorf("assemble BPF instructions: %w", err)
	}
	return h.SetRawBPFFilter(raw)
}

func (h *Handle) SetRawBPFFilter(raw []bpf.RawInstruction) error {
	h.filter = raw
	return h.setFilter()
}

// getEndianness discover the endianness of our current system
func getEndianness() (binary.ByteOrder, error) {
	return binary.NativeEndian, nil
}

//nolint:unused
func htons(in uint16) uint16 {
	return (in<<8)&0xff00 | in>>8
}
