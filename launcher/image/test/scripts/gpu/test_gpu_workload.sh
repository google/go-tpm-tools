 #!/bin/bash
set -euo pipefail
source util/read_serial.sh

# This test requires the workload to run and printing
# corresponding messages to the serial console.
SERIAL_OUTPUT=$(read_serial $1 $2) 
print_serial=false

if echo $SERIAL_OUTPUT | grep -q 'Test PASSED'
then
    echo "- gpu workload running verified"
else
    echo "FAILED: gpu workload not running"
    echo 'TEST FAILED.' > /workspace/status.txt
    print_serial=true
fi