#!/usr/bin/env bash

set -euo pipefail

# Packet capture needs CAP_NET_RAW. Keep default developer and unprivileged CI
# runs clean: integration tests are a no-op unless explicitly run as root.
if [[ ${EUID} -ne 0 ]]; then
	echo "[GO-PCAP INTEGRATION][SKIP] requires root or CAP_NET_RAW (EUID=${EUID})" >&2
	exit 0
fi

source "./test/env.sh"
source "${ROOT_DIR}/test/lib.sh"

trap "integration_test_teardown \$?" EXIT

integration_test_setup

for case in "${ROOT_DIR}"/test/test_*.sh; do
	[[ -f "${case}" ]] || continue
	log_info "start: $(basename "${case}")"

	if ! bash "${case}"; then
		fatal "failed: $(basename "${case}")"
	fi

	log_info "passed: $(basename "${case}")"
done

log_info "all integration tests passed"
