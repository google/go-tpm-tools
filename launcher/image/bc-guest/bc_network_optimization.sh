#!/bin/bash

# Set flag to block concurrent udev-triggered executions of the runtime optimization script
touch /tmp/bc_network_optimizing

wait_stable() {
  local intf="$1"
  local timeout_secs="$2"

  # Wait for physical link/carrier to be restored in sysfs
  local timeout=$((timeout_secs * 2)) # Since we sleep 0.5s
  while [[ "$(cat "/sys/class/net/${intf}/carrier" 2>/dev/null)" != "1" ]]; do
    sleep 0.5
    ((timeout--))
    if ((timeout <= 0)); then
      echo "Timeout waiting for ${intf} carrier" >&2
      break
    fi
  done

  systemd-networkd-wait-online -i "$intf" --timeout="$timeout_secs" || true
}

# --- Configure eth0 ---
wait_stable eth0 30
# Note: changing ring size resets the interface
ethtool -G eth0 rx 2048 tx 2048 tcp-data-split off
wait_stable eth0 30
ethtool -C eth0 adaptive-rx off adaptive-tx off rx-usecs 20 tx-usecs 64

# --- Configure eth1 ---
wait_stable eth1 30
# Note: changing ring size resets the interface
ethtool -G eth1 rx 2048 tx 2048 tcp-data-split off
wait_stable eth1 30
ethtool -C eth1 adaptive-rx off adaptive-tx off rx-usecs 20 tx-usecs 64

# Remove the optimization flag
rm -f /tmp/bc_network_optimizing

# Run runtime optimizations
if [[ -f /usr/share/oem/confidential_space/bc_network_runtime_optimization.sh ]]; then
  /usr/share/oem/confidential_space/bc_network_runtime_optimization.sh
fi