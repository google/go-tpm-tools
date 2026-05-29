#!/bin/bash

# Set flag to block concurrent udev-triggered executions of the runtime optimization script
touch /tmp/bc_network_optimizing

# --- Configure eth0 ---
# 1. Trigger ring size and tcp-data-split reconfiguration (resets the interface)
ethtool -G eth0 rx 2048 tx 2048 tcp-data-split off
# 2. Wait for the physical link/carrier to be restored in sysfs
TIMEOUT=30
while [[ "$(cat /sys/class/net/eth0/carrier 2>/dev/null)" != "1" ]]; do
  sleep 0.5
  ((TIMEOUT--))
  if ((TIMEOUT <= 0)); then
    echo "Timeout waiting for eth0 carrier" >&2
    break
  fi
done
# 3. Block until eth0 is fully back online and stable in systemd-networkd
systemd-networkd-wait-online -i eth0 --timeout=15 || true
# 4. Apply coalescing parameters to the stable, active interface
ethtool -C eth0 adaptive-rx off adaptive-tx off rx-usecs 20 tx-usecs 64

# --- Configure eth1 ---
# 1. Trigger ring size and tcp-data-split reconfiguration (resets the interface)
ethtool -G eth1 rx 2048 tx 2048 tcp-data-split off
# 2. Wait for the physical link/carrier to be restored in sysfs
TIMEOUT=30
while [[ "$(cat /sys/class/net/eth1/carrier 2>/dev/null)" != "1" ]]; do
  sleep 0.5
  ((TIMEOUT--))
  if ((TIMEOUT <= 0)); then
    echo "Timeout waiting for eth1 carrier" >&2
    break
  fi
done
# 3. Block until eth1 is fully back online and stable in systemd-networkd
systemd-networkd-wait-online -i eth1 --timeout=15 || true
# 4. Apply coalescing parameters to the stable, active interface
ethtool -C eth1 adaptive-rx off adaptive-tx off rx-usecs 20 tx-usecs 64

# Remove the optimization flag
rm -f /tmp/bc_network_optimizing

# Run runtime optimizations
if [[ -f /usr/share/oem/confidential_space/bc_network_runtime_optimization.sh ]]; then
  /usr/share/oem/confidential_space/bc_network_runtime_optimization.sh
fi