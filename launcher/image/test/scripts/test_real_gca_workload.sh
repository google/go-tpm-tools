#!/bin/bash
set -euo pipefail
source util/read_serial.sh

SERIAL_OUTPUT=$(read_serial $1 $2)
print_serial=false

if echo $SERIAL_OUTPUT | grep -q 'Workload running'
then
    echo "- workload running verified"
else
    echo "FAILED: workload not running"
    echo 'TEST FAILED.' > /workspace/status.txt
    print_serial=true
fi

if echo $SERIAL_OUTPUT | grep -q 'Token looks okay'
then
    echo "- OIDC token accessible"
else
    echo "FAILED: OIDC token not accessible"
    echo 'TEST FAILED.' > /workspace/status.txt
    print_serial=true
fi

if echo $SERIAL_OUTPUT | grep -q 'iss: fake-issuer-for-testing'
then
    echo "FAILED: token issued by fake verifier instead of real GCA"
    echo 'TEST FAILED.' > /workspace/status.txt
    print_serial=true
else
    echo "- verified token was NOT issued by fake verifier"
fi

if echo $SERIAL_OUTPUT | grep -q 'iss: https://confidentialcomputing.googleapis.com'
then
    echo "- real GCA token issuer verified"
else
    echo "FAILED: real GCA token issuer not verified"
    echo 'TEST FAILED.' > /workspace/status.txt
    print_serial=true
fi

if $print_serial; then
    echo $SERIAL_OUTPUT
fi
