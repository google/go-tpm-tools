#!/bin/bash
set -euo pipefail
source util/read_serial.sh

# Allow VM some time to boot and write to serial console.
sleep 120

SERIAL_OUTPUT=$(read_serial $1 $2)
if echo $SERIAL_OUTPUT | grep -q "$3"
then
    echo "- Health monitoring launch policy verified"
else
    echo "FAILED: Health monitoring launch policy verification"
    echo 'TEST FAILED' > /workspace/status.txt
    echo $SERIAL_OUTPUT
fi
