 #!/bin/bash
set -euo pipefail
source util/read_serial.sh

# If not provided, look up the zone by VM name.
ZONE=${2:-}
if [ -z "$ZONE" ]; then
  ZONE=$(gcloud compute instances list --filter="name=$1" --format='value(zone.basename())')
fi

# This test requires the workload to run and printing
# corresponding messages to the serial console.
SERIAL_OUTPUT=$(read_serial $1 $ZONE) 
print_serial=false

if echo $SERIAL_OUTPUT | grep -q 'unsupported GPU type'
then
    echo "- unsupported GPU types verified"
else
    echo "FAILED: GPU type is not supported"
    echo 'TEST FAILED.' > /workspace/status.txt
    print_serial=true
fi