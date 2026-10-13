#!/bin/bash
set -euo pipefail
source util/read_cloud_logging.sh

VM_NAME=$1
ZONE=$2

MAX_WAIT_SECONDS=300
INTERVAL_SECONDS=10
ELAPSED=0
output=""

verify_logs() {
    echo "$1" | grep -qE '0[[:space:]]+100000[[:space:]]+65536' &&
    echo "$1" | grep -q 'ipv4_status: 200' &&
    echo "$1" | grep -q 'ipv6_status: 200'
}

while [ $ELAPSED -lt $MAX_WAIT_SECONDS ]; do
    output=$(read_cloud_logging "$VM_NAME" || true)
    if verify_logs "$output"; then
        echo "- verified uid_map, ipv4_status: 200, and ipv6_status: 200"
        exit 0
    fi

    vm_status=$(gcloud compute instances describe "$VM_NAME" --zone "$ZONE" --format="value(status)" 2>/dev/null || echo "TERMINATED")
    if [[ "$vm_status" == "TERMINATED" ]]; then
        sleep 5
        output=$(read_cloud_logging "$VM_NAME" || true)
        if verify_logs "$output"; then
            echo "- verified uid_map, ipv4_status: 200, and ipv6_status: 200"
            exit 0
        fi
        break
    fi

    sleep $INTERVAL_SECONDS
    ELAPSED=$((ELAPSED + INTERVAL_SECONDS))
done

echo "FAILED: uid_map, ipv4_status: 200, or ipv6_status: 200 not verified in Cloud Logging"
echo 'TEST FAILED.' > /workspace/status.txt
echo "$output"

