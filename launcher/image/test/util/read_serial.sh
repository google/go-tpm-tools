#!/bin/bash

# read_serial pulls from the global VM_NAME variable and attempts to read the
# entirety of its serial port output.
# Use var=$(read_serial) to capture the output of this command into a variable.
read_serial() {
  local base_cmd='gcloud compute instances get-serial-port-output $VM_NAME --zone us-central1-a 2>/workspace/next_start.txt'
  local serial_out=$(eval ${base_cmd})
  local last=''
  while [ -s /workspace/next_start.txt ]; do
    next=$(cat /workspace/next_start.txt | sed -n 2p | cut -d ' ' -f2)
    # Need to compare the last value to avoid infinite looping with no more data.
    if [[ "$last" == "$next" ]]; then
      break
    fi

    local next_cmd="${base_cmd} ${next}"
    local tmp=$(eval ${next_cmd})
    serial_out="$serial_out $tmp"

    last=$next
  done

  echo $serial_out
}
