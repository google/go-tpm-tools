#!/bin/bash
set -euo pipefail
source util/read_serial.sh

# Allow VM some time to boot and write to serial console.
sleep 120

SERIAL_OUTPUT=$(read_serial $1 $2)
if echo $SERIAL_OUTPUT | grep -q 'logging redirection not allowed by image'
then
    echo "- Log launch policy verified"
else
    echo "FAILED: Log launch policy verification"
    echo 'TEST FAILED' > /workspace/status.txt
    echo $SERIAL_OUTPUT
fi
