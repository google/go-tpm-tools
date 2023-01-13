 #!/bin/bash
set -euo pipefail
source util/read_serial.sh

# This test requires the workload to run and printing
# corresponding messages to the serial console.
SERIAL_OUTPUT=$(read_serial $1 $2) 
print_serial=false

if echo $SERIAL_OUTPUT | grep -q 'workload running'
then
    echo "- workload running verified"
else
    echo "FAILED: workload not running"
    echo 'TEST FAILED.' > /workspace/status.txt
    print_serial=true
fi

if echo $SERIAL_OUTPUT | grep -q 'workload args: \[/main arg_foo\]'
then
    echo "- arguments verified"
else
    echo "FAILED: arguments not verified"
    echo 'TEST FAILED.' > /workspace/status.txt
    print_serial=true
fi

if echo $SERIAL_OUTPUT | grep -q 'env_bar=val_bar'
then
    echo "- env vars verified"
else
    echo "FAILED: env var not verified"
    echo 'TEST FAILED.' > /workspace/status.txt
    print_serial=true
fi

if echo $SERIAL_OUTPUT | grep -q 'token looks okay'
then
    echo "- OIDC token accessible"
else
    echo "FAILED: OIDC token not accessible"
    echo 'TEST FAILED.' > /workspace/status.txt
    print_serial=true
fi

if $print_serial; then
    echo $SERIAL_OUTPUT
fi
