#!/bin/bash

# Function to run when the script receives SIGTERM (shutdown)
cleanup() {
  echo "Caught SIGTERM! Running cleanup script..." | tee /dev/ttyS0 | socat - UDP4:10.138.0.10:2020

  # Call your actual cleanup script here
  /usr/share/oem/confidential_space/container-cleanup.sh

  exit 0
}

# Trap SIGTERM and call the cleanup function
trap 'cleanup' SIGTERM

while true; do
  # Capture the status and dependencies in variables
  STATUS=$(systemctl status cloud-final.service)
  DEPS=$(systemctl list-dependencies cloud-final.service)

  # Pipe everything into socat
  echo "--- HEARTBEAT: $(date) ---
[STATUS]
$STATUS

[DEPENDENCIES]
$DEPS" | socat - UDP4:10.138.0.10:2020

  sleep 5
done
