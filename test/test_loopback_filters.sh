#!/usr/bin/env bash

set -euo pipefail

source "${ROOT_DIR}/test/lib.sh"

udp_trigger() {
	local port=${GO_PCAP_TRAFFIC_PORT:?}
	python3 - "${port}" <<'PY'
import socket
import sys
import time

port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for _ in range(3):
    s.sendto(b"go-pcap", ("127.0.0.1", port))
    time.sleep(0.05)
s.close()
PY
}

tcp_trigger() {
	local port=${GO_PCAP_TRAFFIC_PORT:?}
	python3 - "${port}" <<'PY'
import socket
import sys
import threading
import time

port = int(sys.argv[1])
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", port))
server.listen(1)

def accept_once():
    conn, _ = server.accept()
    try:
        conn.recv(16)
        conn.sendall(b"ok")
    finally:
        conn.close()
        server.close()

t = threading.Thread(target=accept_once)
t.start()
time.sleep(0.1)

client = socket.create_connection(("127.0.0.1", port), timeout=2)
client.sendall(b"go-pcap")
client.recv(2)
client.close()
t.join(timeout=2)
PY
}

run_protocol_cases() {
	local mode=$1
	shift

	local udp_port
	udp_port="$(pick_loopback_port)"
	local tcp_port
	tcp_port="$(pick_loopback_port)"

	run_capture_case "icmp-${mode}" "icmp" icmp_trigger "ICMP echo" "$@"
	GO_PCAP_TRAFFIC_PORT="${udp_port}" run_capture_case "udp-${mode}" "udp and port ${udp_port}" udp_trigger "UDP, length" "$@"
	GO_PCAP_TRAFFIC_PORT="${tcp_port}" run_capture_case "tcp-${mode}" "tcp and port ${tcp_port}" tcp_trigger "Flags [" "$@"
}

run_protocol_cases mmap
run_protocol_cases syscalls --syscalls
