#!/bin/bash

# Disable XPS
echo 0 | tee /sys/class/net/eth0/queues/tx*/xps_cpus
echo 0 | tee /sys/class/net/eth1/queues/tx*/xps_cpus

# NUMA Node enlightment
echo 0 > /sys/class/net/eth0/device/numa_node
echo 1 > /sys/class/net/eth1/device/numa_node

# Ethtool optimizations
ethtool -G eth0 rx 2048 tx 2048
ethtool -G eth1 rx 2048 tx 2048
ethtool -C eth0 adaptive-rx off adaptive-tx off rx-usecs 20 tx-usecs 65
ethtool -C eth1 adaptive-rx off adaptive-tx off rx-usecs 20 tx-usecs 65
ethtool -G eth0 tcp-data-split off
ethtool -G eth1 tcp-data-split off

# Sysctl optimizations
sysctl -w net.core.netdev_budget=600
sysctl -w net.core.netdev_budget_usecs=4000

# IRQ smp affinity optimizations
echo 40-55 | tee /proc/irq/*/idpf-eth0*/../smp_affinity_list > /dev/null
echo 96-111 | tee /proc/irq/*/idpf-eth1*/../smp_affinity_list > /dev/null
