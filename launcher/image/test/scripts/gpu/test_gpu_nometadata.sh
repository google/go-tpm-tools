 #!/bin/bash
set -euo pipefail
source util/read_serial.sh

SERIAL_OUTPUT=$(read_serial $1 $2) 
print_serial=false

if echo $SERIAL_OUTPUT | grep -q 'tee-install-gpu-driver is expected to set to true'
then
    echo "- Verified: missing GPU driver installation flag"
else
    echo "FAILED: Driver installation metadata flag is not set"
    echo 'TEST FAILED.' > /workspace/status.txt
    print_serial=true
fi