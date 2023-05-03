#!/bin/bash
set -euo pipefail
source util/read_serial.sh

SERIAL_OUTPUT=$(read_serial $1 $2) 
# Check MDS variables haven't been changed to use the wrong workload image.
if echo $SERIAL_OUTPUT | grep -v 'Hello from Cloud Run!' 
then 
    echo "- verified changed MDS vars have no effect" 
else
    echo "FAILED: MDS variables changed"
    echo 'TEST FAILED' > /workspace/status.txt
fi
