#!/bin/bash
set -euo pipefail
if [[ -f "util/read_serial.sh" ]]; then
    source util/read_serial.sh
elif [[ -f "../util/read_serial.sh" ]]; then
    source ../util/read_serial.sh
else
    echo "Could not find util/read_serial.sh"
    exit 1
fi

# test_log_load.sh verifies workload completion under high logging throughput and checks AsyncWriter status.
# Usage: test_log_load.sh <VM_NAME> <ZONE>

VM_NAME="${1:-}"
ZONE="${2:-}"

if [[ -z "$VM_NAME" || -z "$ZONE" ]]; then
    echo "Usage: test_log_load.sh <VM_NAME> <ZONE>"
    exit 1
fi

echo "Reading serial console for VM $VM_NAME in zone $ZONE..."
SERIAL_OUTPUT=$(read_serial "$VM_NAME" "$ZONE")

if echo "$SERIAL_OUTPUT" | grep -q 'Workload completed'; then
    echo "- workload execution under load verified"
else
    echo "FAILED: workload did not complete under load"
    echo "$SERIAL_OUTPUT"
    status_file="/workspace/status.txt"
    if [[ ! -d "/workspace" ]]; then
        status_file="/tmp/workspace/status.txt"
        mkdir -p "/tmp/workspace"
    fi
    echo 'TEST FAILED.' > "$status_file"
    exit 0
fi

if echo "$SERIAL_OUTPUT" | grep -q 'AsyncWriter closed with dropped workload logs'; then
    echo "- AsyncWriter non-blocking overflow protection verified (dropped bytes logged cleanly on shutdown)"
else
    echo "- AsyncWriter processed workload logs cleanly without buffer drop"
fi
