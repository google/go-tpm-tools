#!/bin/bash

# --- Configure eth0 ---
# 1. Trigger ring size and tcp-data-split reconfiguration (resets the interface)
ethtool -G eth0 rx 2048 tx 2048 tcp-data-split off
# 2. Block until eth0 is fully back online and stable
systemd-networkd-wait-online -i eth0 --timeout=15 || true
# 3. Apply coalescing parameters to the stable, active interface
ethtool -C eth0 adaptive-rx off adaptive-tx off rx-usecs 20 tx-usecs 64

# --- Configure eth1 ---
# 1. Trigger ring size and tcp-data-split reconfiguration (resets the interface)
ethtool -G eth1 rx 2048 tx 2048 tcp-data-split off
# 2. Block until eth1 is fully back online and stable
systemd-networkd-wait-online -i eth1 --timeout=15 || true
# 3. Apply coalescing parameters to the stable, active interface
ethtool -C eth1 adaptive-rx off adaptive-tx off rx-usecs 20 tx-usecs 64

# Sysctl optimizations
sysctl -w net.core.netdev_budget=600
sysctl -w net.core.netdev_budget_usecs=4000

# Run runtime optimizations
if [[ -f /usr/share/oem/confidential_space/bc_network_runtime_optimization.sh ]]; then
  /usr/share/oem/confidential_space/bc_network_runtime_optimization.sh
fi