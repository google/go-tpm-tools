#!/bin/bash
set -euxo pipefail
source util/read_serial.sh

# Allow VM some time to boot and write to serial console.
sleep 120

SERIAL_OUTPUT=$(read_serial $1 $2)
if echo $SERIAL_OUTPUT | grep -q "$3"
then
    echo "- '$3' found in the VM serial output"
else
    echo "FAILED: '$3' not found in the VM serial output"
    echo 'TEST FAILED.' > /workspace/status.txt
    echo $SERIAL_OUTPUT
fi

