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
    if echo "$output" | grep -qE '0[[:space:]]+100000[[:space:]]+65536'; then
        echo "- verified uid_map: 0 100000 65536"
        exit 0
    fi

    vm_status=$(gcloud compute instances describe "$VM_NAME" --zone "$ZONE" --format="value(status)" 2>/dev/null || echo "TERMINATED")
    if [[ "$vm_status" == "TERMINATED" ]]; then
        sleep 5
        output=$(read_cloud_logging "$VM_NAME" || true)
        if echo "$output" | grep -qE '0[[:space:]]+100000[[:space:]]+65536'; then
            echo "- verified uid_map: 0 100000 65536"
            exit 0
        fi
        break
    fi

    sleep $INTERVAL_SECONDS
    ELAPSED=$((ELAPSED + INTERVAL_SECONDS))
done

echo "FAILED: uid_map 0 100000 65536 not verified in Cloud Logging"
echo 'TEST FAILED.' > /workspace/status.txt
echo "$output"

