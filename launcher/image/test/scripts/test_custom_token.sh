 #!/bin/bash
set -euo pipefail
source util/read_serial.sh

# This test requires the workload to run and print
# corresponding messages to the serial console.
SERIAL_OUTPUT=$(read_serial $2 $3) 
print_serial=false


# if echo $SERIAL_OUTPUT | grep -q "Token valid: $1"
# then
#     echo "- test custom token"
# else
#     echo "FAILED: Could not find 'Token valid: $1' in the serial console"
#     echo "TEST FAILED. Token was expected to pass validation." > /workspace/status.txt
#     print_serial=true
# fi

# if $print_serial; then
#     echo $SERIAL_OUTPUT
# fi
