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

# Disable XPS
echo 0 | tee /sys/class/net/eth0/queues/tx*/xps_cpus 2>/dev/null || true
echo 0 | tee /sys/class/net/eth1/queues/tx*/xps_cpus 2>/dev/null || true

# NUMA Node enlightment
echo 0 | tee /sys/class/net/eth0/device/numa_node 2>/dev/null || true
echo 1 | tee /sys/class/net/eth1/device/numa_node 2>/dev/null || true

# IRQ smp affinity optimizations
echo 40-55 | tee /proc/irq/*/idpf-eth0*/../smp_affinity_list 2>/dev/null || true
echo 96-111 | tee /proc/irq/*/idpf-eth1*/../smp_affinity_list 2>/dev/null || true