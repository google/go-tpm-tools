#!/bin/bash

TARGET_UDP="UDP4:10.138.0.10:2020"

# # Function to run when the script receives SIGTERM (shutdown)
# cleanup() {
#   echo "GDIE Caught SIGTERM! Running cleanup script..." | tee /dev/ttyS0 | socat - $TARGET_UDP
# 
#   # Call your actual cleanup script here
#   # /usr/share/oem/confidential_space/container-cleanup.sh
# 
#   exit 0
# }
# 
# # Trap SIGTERM and call the cleanup function
# trap 'cleanup' SIGTERM
# 
# while true; do
#   # Capture the status, dependencies, and targets in variables
#   STATUS=$(systemctl status cloud-final.service)
#   SYSTEM_STATUS=$(systemctl status)
#   DEPS=$(systemctl list-dependencies cloud-final.service)
#   TARGETS=$(systemctl list-units --type=target)
# 
#   # Pipe everything into socat
#   echo "--- HEARTBEAT: $(date) ---
# [STATUS]
# $STATUS
# 
# [SYSTEM STATUS]
# $SYSTEM_STATUS
# 
# [DEPENDENCIES]
# $DEPS
# 
# [TARGETS]
# $TARGETS" | socat - $TARGET_UDP
# 
#   sleep 5
# done

# New script: Heartbeat every second
echo "--- Investigator Started on $(hostname) ($(hostname -i | awk '{print $1}')): $(date) ---" | socat - $TARGET_UDP

# New script: Listen for commands on UDP 2080 and send output to $TARGET_UDP
while true; do
  cmd=$(socat - UDP-RECVFROM:2080)
  echo "Executing: $cmd"
  eval "$cmd" 2>&1 | socat - $TARGET_UDP
done
