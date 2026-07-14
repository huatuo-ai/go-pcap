#!/usr/bin/env bash

set -euo pipefail

source "${ROOT_DIR}/integration/env.sh"
source "${ROOT_DIR}/integration/lib.sh"

run_capture_case "l2-ethernet-mmap" "icmp" icmp_trigger "ICMPv4"
run_capture_case "l2-ethernet-syscalls" "icmp" icmp_trigger "ICMPv4" --syscalls

run_capture_case "l3-ipv4-mmap" "ip" icmp_trigger "ICMPv4"
run_capture_case "l3-ipv4-syscalls" "ip" icmp_trigger "ICMPv4" --syscalls

if ! ipv6_loopback_available; then
	log_info "SKIP: IPv6 loopback (::1) unavailable on this host"
	exit 0
fi

run_capture_case_l3 "l3-ipv6-mmap" "ip6" icmp6_trigger "IPv6" "ICMPv6"
run_capture_case_l3 "l3-ipv6-syscalls" "ip6" icmp6_trigger "IPv6" "ICMPv6" --syscalls
