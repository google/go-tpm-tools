 #!/bin/bash
set -euxo pipefail
source util/read_serial.sh
source util/read_cloud_logging.sh

# Allow VM some time to boot and write to serial console.
sleep 120

output=""
if [[ "$1" == "serial" ]]; then
    echo "Reading from serial console for VM $3 in zone $4"
    output=$(read_serial $3 $4)
elif [[ "$1" == "cloud_logging" ]]; then
    echo "Reading from cloud logging for VM $3"
    output=$(read_cloud_logging $3)
else 
    echo "Usage: test_log_redirect.sh <serial|cloud_logging> <expectLogs=true|false> <VM_NAME> <ZONE>"
    return 1
fi

if [[ $output != *"Token looks okay"* ]] && [[ "$2" == "true" ]]; then
    echo "FAILED: did not find workload logs in $1, but expected to:"
    echo $output
    echo 'TEST FAILED.' > /workspace/status.txt
elif [[ $output == *"Token looks okay"* ]] && [[ "$2" == "false" ]]; then
    echo "FAILED: found workload logs in $1, but did not expect to:"
    echo $output
    echo 'TEST FAILED.' > /workspace/status.txt
fi

