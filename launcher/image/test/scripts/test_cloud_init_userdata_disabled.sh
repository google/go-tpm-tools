#!/bin/bash
set -euo pipefail
source util/read_serial.sh

echo 'Running cloud-init userdata test'

echo 'Reading from serial port'
SERIAL_OUTPUT=$(read_serial $1 $2)

# check whether ./data/cloud-init-config.yaml is executed, will print "user-data in metadata executed"
# in serial console if it was executed
if echo $SERIAL_OUTPUT | grep -q 'user-data in metadata executed'
then
    echo 'TEST FAILED: user-data executed on the VM'
    echo 'TEST FAILED.' > /workspace/status.txt
else
    echo 'user-data not executed on the VM'
fi
