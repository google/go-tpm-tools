#!/bin/bash

# Function to run when the script receives SIGTERM (shutdown)
cleanup() {
  echo "GDIE Caught SIGTERM! Running cleanup script..." | tee /dev/ttyS0 | socat - UDP4:10.138.0.10:2020

  # Call your actual cleanup script here
  # /usr/share/oem/confidential_space/container-cleanup.sh

  exit 0
}

# Trap SIGTERM and call the cleanup function
trap 'cleanup' SIGTERM

while true; do
  # Capture the status, dependencies, and targets in variables
  STATUS=$(systemctl status cloud-final.service)
  SYSTEM_STATUS=$(systemctl status)
  DEPS=$(systemctl list-dependencies cloud-final.service)
  TARGETS=$(systemctl list-units --type=target)

  # Pipe everything into socat
  echo "--- HEARTBEAT: $(date) ---
[STATUS]
$STATUS

[SYSTEM STATUS]
$SYSTEM_STATUS

[DEPENDENCIES]
$DEPS

[TARGETS]
$TARGETS" | socat - UDP4:10.138.0.10:2020

  sleep 5
done
