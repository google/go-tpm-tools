#!/bin/bash
set -euo pipefail

INTERFACE="${1:-eth1}"

if [[ ! -d "/sys/class/net/${INTERFACE}" ]]; then
  echo "Error: Interface ${INTERFACE} does not exist." >&2
  exit 1
fi

# Get the Device ID (e.g. 0000:00:04.0 or virtio1)
DEV_PATH=$(readlink "/sys/class/net/${INTERFACE}/device")
DEV_ID=$(basename "${DEV_PATH}")

# Get the Driver Name (e.g. virtio_net or idpf)
DRIVER_PATH=$(readlink "/sys/class/net/${INTERFACE}/device/driver")
DRIVER_NAME=$(basename "${DRIVER_PATH}")

# Get the subsystem (pci or virtio)
SUBSYSTEM_PATH=$(readlink "/sys/class/net/${INTERFACE}/device/subsystem")
SUBSYSTEM=$(basename "${SUBSYSTEM_PATH}")

BIND_PATH="/sys/bus/${SUBSYSTEM}/drivers/${DRIVER_NAME}"

# unbind the device
echo "${DEV_ID}" | tee "${BIND_PATH}/unbind" > /dev/null

# Wait for the device to unbind
sleep 1

echo "${DEV_ID}" | tee "${BIND_PATH}/bind" > /dev/null

# Wait for the device to rebind
sleep 1

# Find the new interface name for the device
NEW_INTERFACE=""
for sys_dev in /sys/class/net/*; do
  if [[ -d "${sys_dev}/device" ]]; then
    SYS_DEV_ID=$(basename "$(readlink "${sys_dev}/device")")
    if [[ "${SYS_DEV_ID}" == "${DEV_ID}" ]]; then
      NEW_INTERFACE=$(basename "${sys_dev}")
      break
    fi
  fi
done

if [[ -n "${NEW_INTERFACE}" ]]; then
  # Extract the interface index from the original interface name (e.g. eth0 -> 0, eth1 -> 1)
  INTF_INDEX=$(echo "${INTERFACE}" | tr -cd '0-9')
  if [[ -z "${INTF_INDEX}" ]]; then
    INTF_INDEX=0
  fi

  # Query GCE metadata server for network MTU
  NETWORK_MTU=$(curl -s -f -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/${INTF_INDEX}/mtu" || echo "")

  if [[ -n "${NETWORK_MTU}" ]]; then
    ip link set "${NEW_INTERFACE}" mtu "${NETWORK_MTU}" || true
  fi
fi

