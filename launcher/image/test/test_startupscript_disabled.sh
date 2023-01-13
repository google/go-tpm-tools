#!/bin/bash
set -euo pipefail
source util/read_serial.sh

echo 'Running startup script test'

echo 'Reading from serial port:'
SERIAL_OUTPUT=$(read_serial $1 $2)
echo $SERIAL_OUTPUT

# Without the or logic, this step will fail and cleanup does not run.
# Instead, we put the test assertion output in /workspace/status.txt.
echo $SERIAL_OUTPUT | grep -v 'Executing startup script' || echo 'TEST FAILED' > /workspace/status.txt
