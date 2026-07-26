#!/usr/bin/env bash

set -euo pipefail

log_prefix() {
	echo "[${TEST_LOG_TAG:-GO-PCAP INTEGRATION}]"
}

log_info() {
	echo "$(log_prefix) $*"
}

log_error() {
	echo "$(log_prefix)[ERROR] $*" >&2
}

fatal() {
	echo "$(log_prefix)[FAIL] $*" >&2
	exit 1
}

require_cmd() {
	local cmd=$1
	command -v "$cmd" >/dev/null 2>&1 || fatal "missing required command: ${cmd}"
}

dump_logs_and_fail() {
	local out=$1
	local err=$2
	shift 2

	log_error "----- OUT (${out}) -----"
	[[ -f "$out" ]] && cat "$out" >&2
	log_error "----- ERR (${err}) -----"
	[[ -f "$err" ]] && cat "$err" >&2
	log_error "----- end -----"
	fatal "$*"
}

# Re-send traffic until the capture actually observes it. Firing once after a
# fixed delay races with capture startup: on a slow host the socket is not yet
# listening, the packets are gone for good, and the case fails for no real
# reason. Retrying costs nothing when the first attempt already landed.
trigger_until_captured() {
	local trigger=$1
	local out=$2
	local marker=$3

	local deadline=$((SECONDS + GO_PCAP_TRIGGER_TIMEOUT))
	while :; do
		# A trigger that fails is exactly what the retry is for, so it must not
		# trip set -e. Giving up is reported by the caller's output assertions,
		# which dump the capture logs alongside the failure.
		"${trigger}" || true
		grep -Fq "${marker}" "${out}" && return 0
		((SECONDS < deadline)) || return 1
		sleep "${GO_PCAP_TRIGGER_RETRY_DELAY}"
	done
}

integration_test_setup() {
	[[ -x "${GO_PCAP_BIN}" ]] || fatal "pcap binary not found or not executable: ${GO_PCAP_BIN}"
	require_cmd timeout
	require_cmd ping
	require_cmd python3
}

integration_test_teardown() {
	local exit_code=$1

	if [[ "$exit_code" -eq 0 ]]; then
		rm -rf "${GO_PCAP_TEST_TMPDIR}"
		return 0
	fi

	log_error "integration test failed with exit code: ${exit_code}"
	log_error "temporary artifacts preserved at: ${GO_PCAP_TEST_TMPDIR}"
	exit "$exit_code"
}

pick_loopback_port() {
	python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

icmp_trigger() {
	ping -c "${GO_PCAP_PING_COUNT}" 127.0.0.1 >"${GO_PCAP_TEST_TMPDIR}/icmp.ping" 2>&1
}

run_capture_case() {
	local name=$1
	local filter=$2
	local trigger=$3
	local expected_summary=$4
	shift 4

	local out="${GO_PCAP_TEST_TMPDIR}/${name}.out"
	local err="${GO_PCAP_TEST_TMPDIR}/${name}.err"

	log_info "${name}: capture filter=${filter}"
	timeout "${GO_PCAP_CAPTURE_TIMEOUT}" "${GO_PCAP_BIN}" -nn -i lo "$@" "${filter}" >"${out}" 2>"${err}" &
	local capture_pid=$!

	sleep "${GO_PCAP_START_DELAY}"
	kill -0 "${capture_pid}" 2>/dev/null || dump_logs_and_fail "${out}" "${err}" "${name}: capture exited before traffic"

	# Let the output assertions below report the failure: they dump the capture
	# logs, which a bare set -e abort here would swallow.
	trigger_until_captured "${trigger}" "${out}" "${expected_summary}" || true

	set +e
	wait "${capture_pid}"
	local status=$?
	set -e

	if [[ "${status}" -ne 124 ]]; then
		dump_logs_and_fail "${out}" "${err}" "${name}: capture exited with ${status}, expected timeout exit 124"
	fi

	grep -Fq "${expected_summary}" "${out}" ||
		dump_logs_and_fail "${out}" "${err}" "${name}: expected tcpdump summary ${expected_summary} was not captured"

	local ipv4_packet_pattern='^[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6} '
	if [[ " $* " == *" -e "* ]]; then
		ipv4_packet_pattern+='[^,]+ > [^,]+, ethertype IPv4 \(0x0800\), length [0-9]+: '
	else
		ipv4_packet_pattern+='IP '
	fi
	ipv4_packet_pattern+='127\.0\.0\.1(\.[0-9]+)? > 127\.0\.0\.1(\.[0-9]+)?:'
	grep -Eq "${ipv4_packet_pattern}" "${out}" ||
		dump_logs_and_fail "${out}" "${err}" "${name}: loopback IPv4 packet was not captured"

	if [[ " $* " == *" -e "* ]]; then
		grep -Fq "ethertype IPv4 (0x0800)" "${out}" ||
			dump_logs_and_fail "${out}" "${err}" "${name}: Ethernet header was not printed"
	fi

	log_info "${name}: PASS"
}

run_capture_case_l3() {
	local name=$1
	local filter=$2
	local trigger=$3
	local ip_prefix=$4
	local expected_summary=$5
	shift 5

	local out="${GO_PCAP_TEST_TMPDIR}/${name}.out"
	local err="${GO_PCAP_TEST_TMPDIR}/${name}.err"

	log_info "${name}: capture filter=${filter}"
	timeout "${GO_PCAP_CAPTURE_TIMEOUT}" "${GO_PCAP_BIN}" -nn -i lo "$@" "${filter}" >"${out}" 2>"${err}" &
	local capture_pid=$!

	sleep "${GO_PCAP_START_DELAY}"
	kill -0 "${capture_pid}" 2>/dev/null ||
		dump_logs_and_fail "${out}" "${err}" "${name}: capture exited before traffic"

	trigger_until_captured "${trigger}" "${out}" "${expected_summary}" || true

	set +e
	wait "${capture_pid}"
	local status=$?
	set -e

	if [[ "${status}" -ne 124 ]]; then
		dump_logs_and_fail "${out}" "${err}" "${name}: capture exited with ${status}, expected timeout exit 124"
	fi

	grep -Fq "${expected_summary}" "${out}" ||
		dump_logs_and_fail "${out}" "${err}" "${name}: expected tcpdump summary ${expected_summary} was not captured"

	grep -Eq "^[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{6} ${ip_prefix} ::1 > ::1:" "${out}" ||
		dump_logs_and_fail "${out}" "${err}" "${name}: IPv6 loopback packet was not captured"

	log_info "${name}: PASS"
}

ipv6_loopback_available() {
	ping -6 -c1 -W1 ::1 >/dev/null 2>&1
}

icmp6_trigger() {
	ping -6 -c "${GO_PCAP_PING_COUNT}" ::1 >"${GO_PCAP_TEST_TMPDIR}/icmp6.ping" 2>&1
}
