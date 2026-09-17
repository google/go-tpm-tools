#!/bin/bash
set -euo pipefail
source util/read_serial.sh

SERIAL_OUTPUT=$(read_serial $1 $2)
print_serial=false

if echo "$SERIAL_OUTPUT" | grep -q 'Successfully created challenge'
then
    echo "- challenge creation verified"
else
    echo "FAILED: challenge creation failed (GCA client creation or VM startup failed)"
    echo 'TEST FAILED.' > /workspace/status.txt
    print_serial=true
fi

if $print_serial; then
    echo "$SERIAL_OUTPUT"
fi
