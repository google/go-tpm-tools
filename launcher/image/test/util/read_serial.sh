#!/bin/bash

# read_serial attempts to read the serial output until the workload is finished
# Use var=$(read_serial <VM_NAME> <ZONE>) to capture the output of this command into a variable.
read_serial() {
  local base_cmd="gcloud compute instances get-serial-port-output $1 --zone $2"
  local start_offset=0
  local serial_file="/workspace/full_serial_$1.txt"

  local timeout="10 minute"
  local endtime=$(date -ud "$timeout" +%s)

  >&2 echo "Reading serial console..."
  while [[ $(date -u +%s) -lt $endtime ]]; do
    local raw_json
    raw_json=$(eval "${base_cmd} --start=${start_offset} --format=json" 2>/dev/null)

    if [ -z "$raw_json" ]; then
      >&2 echo "VM stopped (could not fetch serial port output)"
      break
    fi

    printf '%s' "$raw_json" | python3 -c "import sys, json; sys.stdout.write(json.load(sys.stdin).get('contents', ''))" >> "$serial_file"
    start_offset=$(printf '%s' "$raw_json" | python3 -c "import sys, json; print(json.load(sys.stdin).get('next', ''))")

    if grep -q "TEE container launcher exiting" "$serial_file" 2>/dev/null; then
      break
    fi

    sleep 5
  done

  cat "$serial_file"
}
