#!/bin/bash
set -euo pipefail
source util/read_serial.sh

SERIAL_OUTPUT=$(read_serial $1 $2)
EXPECTED="uid_map: 0 100000 65536"
if [[ "$SERIAL_OUTPUT" == *"$EXPECTED"* ]]; then
    echo "- verified $EXPECTED"
else
    echo "FAILED: $EXPECTED not verified"
    echo 'TEST FAILED.' > /workspace/status.txt
    echo "$SERIAL_OUTPUT"
fi
