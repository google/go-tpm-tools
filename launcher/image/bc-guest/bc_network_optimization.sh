#!/bin/bash

# Ethtool optimizations
# Configure eth0
ethtool -G eth0 rx 2048 tx 2048 tcp-data-split off
ethtool -C eth0 adaptive-rx off adaptive-tx off rx-usecs 20 tx-usecs 64

# Block until systemd-networkd reports eth0 is fully back online (up to 15 seconds)
systemd-networkd-wait-online -i eth0 --timeout=15 || true

# Configure eth1
ethtool -G eth1 rx 2048 tx 2048 tcp-data-split off
ethtool -C eth1 adaptive-rx off adaptive-tx off rx-usecs 20 tx-usecs 64

# Block until systemd-networkd reports eth1 is fully back online (up to 15 seconds)
systemd-networkd-wait-online -i eth1 --timeout=15 || true


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