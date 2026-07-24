 #!/bin/bash
set -euo pipefail
source util/read_serial.sh

# This test requires the workload to run and printing
# corresponding messages to the serial console.
SERIAL_OUTPUT=$(read_serial $1 $2) 
print_serial=false

if echo $SERIAL_OUTPUT | grep -q 'failed to get the GPU type info'
then
    echo "- no GPU verified"
else
    echo "FAILED: GPU not detected"
    echo 'TEST FAILED.' > /workspace/status.txt
    print_serial=true
fi