#!/bin/bash
set -euo pipefail

MONITOR_VM=$1
WORKLOAD_VM=$2
ZONE=$3

timeout_seconds=600
start_time=$(date +%s)

check_timeout() {
  local current_time=$(date +%s)
  local elapsed=$((current_time - start_time))
  local remaining=$((timeout_seconds - elapsed))
  if [ $remaining -le 0 ]; then
    echo "failed: $1" > /workspace/status.txt
    exit 0
  fi
  echo $remaining
}

echo "Starting to tail serial port in background..."
gcloud compute instances tail-serial-port-output $MONITOR_VM --zone $ZONE > /workspace/serial_output.txt &
TAIL_PID=$!

# Give gcloud a few seconds to establish the connection
sleep 5

echo "Polling for heartbeat (Workload: $WORKLOAD_VM, Monitor: $MONITOR_VM)..."
remaining=$(check_timeout "Timeout before heartbeat poll")
timeout $remaining bash -c "until grep -q 'Workload heartbeat' /workspace/serial_output.txt; do sleep 1; done" || {
  echo "failed: Heartbeat not found within timeout" > /workspace/status.txt
  kill $TAIL_PID
  exit 0
}

echo "Stopping workload VM..."
gcloud compute instances stop $WORKLOAD_VM --zone $ZONE

echo "Polling for graceful exit..."
remaining=$(check_timeout "Timeout before graceful exit poll")
timeout $remaining bash -c "until grep -q 'Workload exiting gracefully' /workspace/serial_output.txt; do sleep 1; done" || {
  echo "failed: Graceful exit message not found within timeout" > /workspace/status.txt
  kill $TAIL_PID
  exit 0
}

# Success! Clean up the background process
kill $TAIL_PID
