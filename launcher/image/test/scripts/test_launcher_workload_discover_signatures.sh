#!/bin/bash
set -euxo pipefail
source util/read_serial.sh

# This test requires the workload to run and printing
# corresponding messages to the serial console.
SERIAL_OUTPUT=$(read_serial $1 $2) 
print_serial=false

# Check how many times "Found container image signatures" is being logged.
counts=$(echo $SERIAL_OUTPUT | grep -o 'Found container image signatures' | wc -l)
if [ $counts -eq $3 ]; then
    echo "- container image signatures found with expected counts: $3"
else
    echo "FAILED: container image signatures want $3 counts, but got $counts"
    echo 'TEST FAILED.' > /workspace/status.txt
    print_serial=true
fi

if $print_serial; then
    echo $SERIAL_OUTPUT
fi
