#!/bin/bash

# read_serial attempts to read the serial output until the workload is finished
# Use var=$(read_serial <VM_NAME> <ZONE>) to capture the output of this command into a variable.
read_serial() {
  local base_cmd='gcloud compute instances get-serial-port-output $1 --zone $2 2>/workspace/next_start.txt'
  local serial_out=$(eval ${base_cmd})
  local last=''

  # timeout after 10 min
  timeout="10 minute"
  endtime=$(date -ud "$timeout" +%s)

  echo "Reading serial console..."
  while [ -s /workspace/next_start.txt ]; do
    if [[ $(date -u +%s) -ge $endtime ]]; then
      echo "timed out reading serial console" 
      break
    fi

    next=$(cat /workspace/next_start.txt | sed -n 2p | cut -d ' ' -f2)
    local next_cmd="${base_cmd} ${next}"
    
    # sleeping 5s for the next serial console read"
    sleep 5

    local tmp=$(eval ${next_cmd})
    serial_out="$serial_out $tmp"

    # break the loop if the workload is finished
    if echo ${serial_out} | grep -qi "TEE container launcher exiting"; then
      break
    fi

    last=$next
  done

  echo $serial_out
}
