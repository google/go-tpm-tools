 #!/bin/bash
set -euo pipefail
source util/read_serial.sh

# This test requires the workload to run and printing
# corresponding messages to the serial console.
SERIAL_OUTPUT=$(read_serial $1 $2) 
print_serial=false

if echo $SERIAL_OUTPUT | grep -q 'unsupported gpu type'
then
    echo "- unsupported gpu types verified"
else
    echo "FAILED: gpu type is not supported"
    echo 'TEST FAILED.' > /workspace/status.txt
    print_serial=true
fi