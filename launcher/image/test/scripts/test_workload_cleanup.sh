#!/bin/bash
set -euxo pipefail

MONITOR_VM=$1
WORKLOAD_VM=$2
ZONE=$3
SERIAL_LOG="/workspace/serial_output_gracefulshutdown.txt"
GRACEFUL_MSG="Workload exiting gracefully"

HEARTBEAT_TIMEOUT_SECONDS=600
SHUTDOWN_TIMEOUT_SECONDS=180

echo "Starting to tail serial port in background..."
gcloud compute instances tail-serial-port-output $MONITOR_VM --zone $ZONE > "$SERIAL_LOG" &
TAIL_PID=$!

# Give gcloud a few seconds to establish the connection
sleep 5

echo "Polling for heartbeat (Workload: $WORKLOAD_VM, Monitor: $MONITOR_VM)..."
if ! timeout $HEARTBEAT_TIMEOUT_SECONDS bash -c "until grep -q 'Workload heartbeat' \"$SERIAL_LOG\"; do sleep 1; done"; then
  echo "failed: Heartbeat not found within timeout" > /workspace/status.txt
  echo "=== Workload VM Serial Console Output ==="
  gcloud compute instances get-serial-port-output $WORKLOAD_VM --zone $ZONE || true
  echo "=== Monitor VM Serial Console Output ==="
  cat "$SERIAL_LOG" || true
  kill $TAIL_PID 2>/dev/null || true
  exit 0
fi

echo "Stopping workload VM..."
gcloud compute instances stop $WORKLOAD_VM --zone $ZONE &

echo "Polling for graceful exit..."
if ! timeout $SHUTDOWN_TIMEOUT_SECONDS bash -c "until grep -q '$GRACEFUL_MSG' \"$SERIAL_LOG\"; do sleep 1; done"; then
  echo "failed: Graceful exit message not found within timeout" > /workspace/status.txt
  echo "=== Workload VM Serial Console Output ==="
  gcloud compute instances get-serial-port-output $WORKLOAD_VM --zone $ZONE || true
  echo "=== Monitor VM Serial Console Output ==="
  cat "$SERIAL_LOG" || true
  kill $TAIL_PID 2>/dev/null || true
  exit 0
fi

# Success! Clean up the background process
kill $TAIL_PID 2>/dev/null || true
