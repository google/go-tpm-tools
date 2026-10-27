#!/bin/bash
set -euo pipefail
source util/read_cloud_logging.sh

VM_NAME=$1
ZONE=$2

MAX_WAIT_SECONDS=300
INTERVAL_SECONDS=10
ELAPSED=0
output=""

while [ $ELAPSED -lt $MAX_WAIT_SECONDS ]; do
    output=$(read_cloud_logging "$VM_NAME" || true)
    # Stop once both checks have reported a result (ok or failed) and the launcher has logged the
    # workload's exit status. Cloud Logging can show entries out of order, so the launcher's exit
    # message alone doesn't mean the earlier entries are visible yet.
    if echo "$output" | grep -qE 'ipv4_reachability: (ok|failed)' &&
        echo "$output" | grep -qE 'ipv6_reachability: (ok|failed)' &&
        echo "$output" | grep -q 'workload task ended and returned'; then
        break
    fi

    vm_status=$(gcloud compute instances describe "$VM_NAME" --zone "$ZONE" --format="value(status)" 2>/dev/null || echo "TERMINATED")
    if [[ "$vm_status" == "TERMINATED" ]]; then
        sleep 5
        output=$(read_cloud_logging "$VM_NAME" || true)
        break
    fi

    sleep $INTERVAL_SECONDS
    ELAPSED=$((ELAPSED + INTERVAL_SECONDS))
done

failed=false
expect() {
    if echo "$output" | grep -qE "$1"; then
        echo "- verified $2"
    else
        echo "FAILED: $2 not verified in Cloud Logging"
        failed=true
    fi
}

expect 'workload task ended and returned 0' 'workload exited with 0'
expect '0[[:space:]]+100000[[:space:]]+65536' 'uid_map: 0 100000 65536'
expect 'ipv4_reachability: ok' 'IPv4 egress reachability'
expect 'ipv6_reachability: ok' 'IPv6 egress reachability'

if $failed; then
    echo 'TEST FAILED.' > /workspace/status.txt
    echo "$output"
fi

