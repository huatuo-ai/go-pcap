// Copyright 2020 Avi Deitcher
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

package pcap

/*
 MacOS uses a /dev/bpf* device instead of a raw socket. Some good examples:
  https://github.com/c-bata/xpcap/blob/master/sniffer.c#L50
  https://gist.github.com/2opremio/6fda363ab384b0d85347956fb79a3927
 Linux uses a raw socket.
  For syscall-based capture: see http://www.microhowto.info/howto/capture_ethernet_frames_using_an_af_packet_socket_in_c.html
  For mmap-based capture: see http://www.microhowto.info/howto/capture_ethernet_frames_using_an_af_packet_ring_buffer_in_c.html

Important references:
 - https://www.tcpdump.org/manpages/pcap-filter.7.html - canonical reference for the filter language
 - https://www.freebsd.org/cgi/man.cgi?query=bpf&sektion=4&manpath=FreeBSD+4.7-RELEASE - BPF compilation
 - https://www.kernel.org/doc/Documentation/networking/filter.txt - Linux
 - https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt - Linux mmap packet capture
 - https://en.wikipedia.org/wiki/EtherType
 - https://en.wikipedia.org/wiki/Address_Resolution_Protocol
 - https://en.wikipedia.org/wiki/IPv4
 - https://en.wikipedia.org/wiki/IPv6_packet
 - https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers

 Notes: ethernet header is 14 bytes (6 src, 6 dst, 2 payload type)


*/
