 #!/bin/bash
set -euxo pipefail
source util/read_serial.sh
source util/read_cloud_logging.sh

output=""
if [[ "$1" == "serial" ]]; then
    # read_serial has built-in dynamic polling and waits for task exit.
    echo "Reading from serial console for VM $3 in zone $4"
    output=$(read_serial $3 $4)
elif [[ "$1" == "cloud_logging" ]]; then
    echo "Polling cloud logging for VM $3 in zone $4"
    MAX_WAIT_SECONDS=600
    INTERVAL_SECONDS=15
    ELAPSED=0
    while [ $ELAPSED -lt $MAX_WAIT_SECONDS ]; do
        output=$(read_cloud_logging $3 || true)
        
        # If logs are expected and found, return early
        if [[ $output == *"Token looks okay"* ]] && [[ "$2" == "true" ]]; then
            break
        fi

        # Check if VM is done running
        vm_status=$(gcloud compute instances describe "$3" --zone "$4" --format="value(status)" || echo "TERMINATED")
        if [[ "$vm_status" == "TERMINATED" ]]; then
            break
        fi

        sleep $INTERVAL_SECONDS
        ELAPSED=$((ELAPSED + INTERVAL_SECONDS))
    done
else 
    echo "Usage: test_log_redirect.sh <serial|cloud_logging> <expectLogs=true|false> <VM_NAME> <ZONE>"
    exit 1
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

