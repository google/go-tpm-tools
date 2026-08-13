#!/bin/bash

# read_serial attempts to read the serial output until the workload is finished
# Use var=$(read_serial <VM_NAME> <ZONE>) to capture the output of this command into a variable.
read_serial() {
  local vm="$1"
  local zone="$2"
  local start_offset=0
  local serial_out=""
  local timeout="10 minute"
  local endtime=$(date -ud "$timeout" +%s)

  while [[ $(date -u +%s) -lt $endtime ]]; do
    local resp=$(gcloud compute instances get-serial-port-output "$vm" --zone="$zone" --start="${start_offset}" --format=json 2>/dev/null)

    if [ -n "$resp" ]; then
      local chunk
      chunk=$(printf '%s' "$resp" | python3 -c "import sys, json; print(json.load(sys.stdin).get('contents', ''), end='')")
      start_offset=$(printf '%s' "$resp" | python3 -c "import sys, json; print(json.load(sys.stdin).get('next', '0'))")
      serial_out="${serial_out}${chunk}"
    else
      local status
      status=$(gcloud compute instances describe "$vm" --zone="$zone" --format="value(status)")
      if [[ "$status" == "TERMINATED" || "$status" == "STOPPING" ]]; then
        >&2 echo "Instance ${vm} is ${status,,}."
        break
      fi
      >&2 echo "Empty response from get-serial-port-output for ${vm} (instance status: ${status})."
    fi

    if [[ "$serial_out" == *"TEE container launcher exiting"* ]]; then
      break
    fi

    sleep 5
  done

  printf '%s\n' "$serial_out"
}
