#!/bin/bash
set -euxo pipefail

MONITOR_VM=$1
WORKLOAD_VM=$2
ZONE=$3
SERIAL_LOG="/workspace/serial_output_nonroot.txt"

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

confirm_log() {
  local expected="$1"
  local remaining=$(check_timeout "Timeout before poll for '$expected'")
  timeout $remaining bash -c "until grep -q '$expected' \"$SERIAL_LOG\"; do sleep 1; done" || {
    echo "failed: '$expected' not found within timeout" > /workspace/status.txt
    date
    kill $TAIL_PID || true
    exit 0
  }
  echo "Confirmed: $(grep -m 1 "$expected" "$SERIAL_LOG")"
}

echo "Starting to tail serial port in background..."
gcloud compute instances tail-serial-port-output $MONITOR_VM --zone $ZONE > "$SERIAL_LOG" &
TAIL_PID=$!

# Give gcloud a few seconds to establish the connection
sleep 5

echo "Polling for complete process tree (Workload: $WORKLOAD_VM, Monitor: $MONITOR_VM)..."
date
confirm_log "fork-parent: 0"
confirm_log "fork-child1: 101"
confirm_log "fork-child2: 909"

# Success! Clean up the background process
kill $TAIL_PID || true
