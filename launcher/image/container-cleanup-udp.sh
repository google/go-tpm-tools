#!/bin/bash

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
