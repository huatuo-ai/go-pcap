// Copyright 2026 The HuaTuo Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

package pcap

import (
	"bytes"
	"testing"

	"github.com/gopacket/gopacket"
	syscall "golang.org/x/sys/unix"
)

func TestRestoreVLANTag(t *testing.T) {
	t.Parallel()

	ethernetIPv4 := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
		0x08, 0x00, 0x45, 0x00,
	}
	taggedVLAN3 := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
		0x81, 0x00, 0x00, 0x03,
		0x08, 0x00, 0x45, 0x00,
	}
	taggedVLAN0 := append([]byte(nil), taggedVLAN3...)
	taggedVLAN0[15] = 0
	taggedQinQ := append([]byte(nil), taggedVLAN3...)
	taggedQinQ[12] = 0x88
	taggedQinQ[13] = 0xa8

	tests := []struct {
		name         string
		data         []byte
		metadata     vlanMetadata
		wantData     []byte
		wantLength   int
		wantCaptured int
	}{
		{
			name:         "vlan 3 defaults to 802.1Q",
			data:         ethernetIPv4,
			metadata:     vlanMetadata{tci: 3},
			wantData:     taggedVLAN3,
			wantLength:   20,
			wantCaptured: 20,
		},
		{
			name: "vlan 0 uses valid status",
			data: ethernetIPv4,
			metadata: vlanMetadata{
				status: syscall.TP_STATUS_VLAN_VALID,
			},
			wantData:     taggedVLAN0,
			wantLength:   20,
			wantCaptured: 20,
		},
		{
			name: "explicit QinQ TPID",
			data: ethernetIPv4,
			metadata: vlanMetadata{
				status: syscall.TP_STATUS_VLAN_VALID | syscall.TP_STATUS_VLAN_TPID_VALID,
				tci:    3,
				tpid:   0x88a8,
			},
			wantData:     taggedQinQ,
			wantLength:   20,
			wantCaptured: 20,
		},
		{
			name:         "no VLAN metadata",
			data:         ethernetIPv4,
			metadata:     vlanMetadata{},
			wantData:     ethernetIPv4,
			wantLength:   16,
			wantCaptured: 16,
		},
		{
			name:         "truncated Ethernet header",
			data:         ethernetIPv4[:11],
			metadata:     vlanMetadata{tci: 3},
			wantData:     ethernetIPv4[:11],
			wantLength:   11,
			wantCaptured: 11,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ci := gopacket.CaptureInfo{
				Length:        len(test.data),
				CaptureLength: len(test.data),
			}
			gotData, gotCI := restoreVLANTag(test.data, ci, test.metadata)
			if !bytes.Equal(gotData, test.wantData) {
				t.Errorf("restoreVLANTag() data = %x, want %x", gotData, test.wantData)
			}
			if gotCI.Length != test.wantLength {
				t.Errorf("restoreVLANTag() length = %d, want %d", gotCI.Length, test.wantLength)
			}
			if gotCI.CaptureLength != test.wantCaptured {
				t.Errorf(
					"restoreVLANTag() capture length = %d, want %d",
					gotCI.CaptureLength,
					test.wantCaptured,
				)
			}
		})
	}
}
