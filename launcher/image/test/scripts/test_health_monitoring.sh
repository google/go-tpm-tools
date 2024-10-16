#!/bin/bash
set -euxo pipefail
source util/read_serial.sh

# This test requires the workload to run and printing
# corresponding messages to the serial console.
SERIAL_OUTPUT=$(read_serial $1 $2) 
print_serial=false

if echo $SERIAL_OUTPUT | grep -q 'node-problem-detector.service successfully started'
then
    echo "- memory monitoring enabled"
else
    echo "FAILED: memory monitoring disabled"
    echo 'TEST FAILED.' > /workspace/status.txt
    print_serial=true
fi

if $print_serial; then
    echo $SERIAL_OUTPUT
fi