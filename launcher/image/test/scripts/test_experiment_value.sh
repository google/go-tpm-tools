 #!/bin/bash
set -euo pipefail
source util/read_serial.sh

# This test requires the workload to run and print
# corresponding messages to the serial console.
SERIAL_OUTPUT=$(read_serial $2 $3) 
print_serial=false

if echo $SERIAL_OUTPUT | grep -q "EnableTestFeatureForImage:$1"
then
    echo "- test experiment verified $1"
else
    echo "FAILED: experiment status expected to be $1"
    echo "TEST FAILED. Test experiment status expected to be $1" > /workspace/status.txt
    print_serial=true
fi

if $print_serial; then
    echo $SERIAL_OUTPUT
fi
