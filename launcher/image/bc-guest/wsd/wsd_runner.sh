#!/bin/bash
set -e

if [ -f /usr/share/oem/wsd/image.env ]; then
    source /usr/share/oem/wsd/image.env
else
    echo "Error: Config file not found!"
    exit 1
fi

echo "=== Launching Workload Service Daemon Container ==="

echo "Checking for existing container..."
if ctr container info "$CONTAINER_NAME" >/dev/null 2>&1; then
    echo "Removing existing container..."
    ctr container rm "$CONTAINER_NAME"
fi

ctr run --rm --net-host \
  --mount "type=bind,src=/tmp/container_launcher/,dst=/run/container_launcher/,options=rbind:rw" \
  --mount "type=tmpfs,dst=/tmp" \
  --env SERVICE_ROLE="SERVICE_ROLE_WSD" \
  --env KEY_PROTECTION_MECHANISM="KEY_PROTECTION_VM" \
  --env KPS_IP="${KPS_VM_IP}" \
  --rootfs /usr/share/oem/wsd/rootfs \
  "$CONTAINER_NAME" \
  /usr/local/bin/agent --kps-vm-ip="${KPS_VM_IP}" --socket="/run/container_launcher/kmaserver.sock"
