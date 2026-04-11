#!/bin/bash

while true; do
  # Capture the status in a variable
  STATUS=$(systemctl status cloud-final.service)

  # Pipe the heartbeat and status into socat
  echo "--- HEARTBEAT: $(date) ---
$STATUS" | socat - UDP4:10.138.0.10:2020

  sleep 1
done
