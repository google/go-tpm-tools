#!/bin/bash

# read_serial attempts to read the serial output until the workload is finished
# Use var=$(read_serial <VM_NAME> <ZONE>) to capture the output of this command into a variable.
read_serial() {
  local vm_name="$1"
  local zone="$2"
  local base_cmd="gcloud compute instances get-serial-port-output ${vm_name} --zone ${zone} 2>&1"
  local serial_out=""

  # timeout after 10 min
  local timeout="10 minute"
  local endtime=$(date -ud "$timeout" +%s)

  echo "Reading serial console..."
  while [[ $(date -u +%s) -lt $endtime ]]; do
    local tmp=$(eval ${base_cmd})
    serial_out="${serial_out} ${tmp}"

    # break the loop if the workload is finished or VM stopped
    if echo "${serial_out}" | grep -qi "TEE container launcher exiting\|Could not fetch serial port output\|VM stopped"; then
      break
    fi

    # sleeping 5s for the next serial console read
    sleep 5
  done

  echo "${serial_out}"
}
