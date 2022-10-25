#!/bin/bash
set -euo pipefail
source util/read_serial.sh

echo 'Running startup script test'
VM_NAME=$(cat /workspace/vm_name.txt)

echo 'Sleeping to allow startup script to run'
sleep 5

echo 'Reading from serial port:'
SERIAL_OUTPUT=$(read_serial)
echo $SERIAL_OUTPUT

# Without the or logic, this step will fail and cleanup does not run.
# Instead, we put the test assertion output in /workspace/status.txt.
echo $SERIAL_OUTPUT | grep -v 'Executing startup script' || echo 'TEST FAILED' > /workspace/status.txt
