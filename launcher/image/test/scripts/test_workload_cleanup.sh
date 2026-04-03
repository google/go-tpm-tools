#!/bin/bash
set -euo pipefail

MONITOR_VM=$1
WORKLOAD_VM=$2
ZONE=$3

timeout_seconds=300
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

echo "Polling for heartbeat..."
remaining=$(check_timeout "Timeout before heartbeat poll")
timeout $remaining \
  gcloud compute instances tail-serial-port-output $MONITOR_VM --zone $ZONE | \
  grep -q 'Workload heartbeat' || \
  { echo "failed: Heartbeat not found within timeout" > /workspace/status.txt; exit 0; }

echo "Stopping workload VM..."
gcloud compute instances stop $WORKLOAD_VM --zone $ZONE

echo "Polling for graceful exit..."
remaining=$(check_timeout "Timeout before graceful exit poll")
timeout $remaining \
  gcloud compute instances tail-serial-port-output $MONITOR_VM --zone $ZONE | \
  grep -q 'Workload exiting gracefully' || \
  { echo "failed: Graceful exit message not found within timeout" > /workspace/status.txt; exit 0; }
