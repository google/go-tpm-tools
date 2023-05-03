#!/bin/bash
set -euo pipefail
source util/read_serial.sh

# Allow VM some time to boot and write to serial console.
sleep 120

SERIAL_OUTPUT=$(read_serial $1 $2)
if echo $SERIAL_OUTPUT | grep -q --fixed-strings 'env var {OUT a} is not allowed to be overridden on this image; allowed envs to be overridden: [ALLOWED_OVERRIDE]'
then
    echo "- Env launch policy verified"
else
    echo "FAILED: Env launch policy verification"
    echo 'TEST FAILED' > /workspace/status.txt
    echo $SERIAL_OUTPUT
fi
