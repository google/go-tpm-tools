#!/bin/bash
set -euo pipefail
source util/read_serial.sh

# This test requires the workload to run and print
# corresponding messages to the serial console.
SERIAL_OUTPUT=$(read_serial $1 $2) 
print_serial=false

if echo "$SERIAL_OUTPUT" | grep -q "Success! Flow completed."; then
    echo "- test keymanager"
else
    echo "FAILED: Could not find 'Success! Flow completed.' in the serial console"
    echo "TEST FAILED. Keymanager flow was expected to pass validation." > /workspace/status.txt
    print_serial=true
fi

if $print_serial; then
    echo "$SERIAL_OUTPUT"
fi
