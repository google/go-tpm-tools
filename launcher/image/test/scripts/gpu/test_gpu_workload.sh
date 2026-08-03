 #!/bin/bash
set -euo pipefail
source util/read_serial.sh

# This test requires the workload to run and printing
# corresponding messages to the serial console.
SERIAL_OUTPUT=$(read_serial $1 $2) 
print_serial=false

# CUDA sample workload code : https://github.com/NVIDIA/cuda-samples/blob/master/Samples/0_Introduction/vectorAdd/vectorAdd.cu#L176
if echo $SERIAL_OUTPUT | grep -q 'Test PASSED'
then
    echo "- GPU workload running verified"
else
    echo "FAILED: GPU workload not running"
    echo 'TEST FAILED.' > /workspace/status.txt
    print_serial=true
fi

if echo $SERIAL_OUTPUT | grep -q 'Successfully measured device attestation binding events and enabled ready states'
then
    echo "- GPU attestation collection verified"
else
    echo "FAILED: GPU attestation not collected"
    echo 'TEST FAILED.' > /workspace/status.txt
    print_serial=true
fi

if $print_serial; then
    echo "$SERIAL_OUTPUT"
fi