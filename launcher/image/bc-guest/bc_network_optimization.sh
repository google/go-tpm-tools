#!/bin/bash

# Ethtool optimizations
# Perform these first - setting ring length will reset other settings
ethtool -G eth0 rx 2048 tx 2048
ethtool -G eth1 rx 2048 tx 2048
ethtool -C eth0 adaptive-rx off adaptive-tx off rx-usecs 20 tx-usecs 64
ethtool -C eth1 adaptive-rx off adaptive-tx off rx-usecs 20 tx-usecs 64
ethtool -G eth0 tcp-data-split off
ethtool -G eth1 tcp-data-split off

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