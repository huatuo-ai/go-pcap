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

run_capture_case() {
	local name=$1
	local filter=$2
	local trigger=$3
	local expected_layer=$4
	shift 4

	local out="${GO_PCAP_TEST_TMPDIR}/${name}.out"
	local err="${GO_PCAP_TEST_TMPDIR}/${name}.err"

	log_info "${name}: capture filter=${filter}"
	timeout "${GO_PCAP_CAPTURE_TIMEOUT}" "${GO_PCAP_BIN}" -i lo "$@" "${filter}" >"${out}" 2>"${err}" &
	local capture_pid=$!

	sleep "${GO_PCAP_START_DELAY}"
	kill -0 "${capture_pid}" 2>/dev/null || dump_logs_and_fail "${out}" "${err}" "${name}: capture exited before traffic"

	"${trigger}"

	set +e
	wait "${capture_pid}"
	local status=$?
	set -e

	if [[ "${status}" -ne 124 ]]; then
		dump_logs_and_fail "${out}" "${err}" "${name}: capture exited with ${status}, expected timeout exit 124"
	fi

	grep -q "PACKET LAYER 2: ${expected_layer}" "${out}" ||
		dump_logs_and_fail "${out}" "${err}" "${name}: expected layer ${expected_layer} was not captured"

	grep -q "From src \\[127 0 0 1\\] to dst \\[127 0 0 1\\]" "${out}" ||
		dump_logs_and_fail "${out}" "${err}" "${name}: loopback IPv4 packet was not captured"

	log_info "${name}: PASS"
}
