#!/bin/bash

# XPS mapping for NIC 1 (Maps to Application cores 40-55)
CPU_START=40
for i in {0..15}; do
    CPU_ID=$((CPU_START + i))
    BLOCK=$((CPU_ID / 32))
    BIT=$((CPU_ID % 32))
    MASK=$(printf "%x" $((1 << BIT)))
    for ((j=0; j<BLOCK; j++)); do MASK+=",00000000"; done
    echo $MASK > /sys/class/net/eth0/queues/tx-$i/xps_cpus
done

# XPS mapping for NIC 2 (Maps to Application cores 96-111)
CPU_START=96
for i in {0..15}; do
    CPU_ID=$((CPU_START + i))
    BLOCK=$((CPU_ID / 32))
    BIT=$((CPU_ID % 32))
    MASK=$(printf "%x" $((1 << BIT)))
    for ((j=0; j<BLOCK; j++)); do MASK+=",00000000"; done
    echo $MASK > /sys/class/net/eth1/queues/tx-$i/xps_cpus
done

# NUMA Node optimizations
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
echo 24-39 | tee /proc/irq/*/idpf-eth0*/../smp_affinity_list > /dev/null
echo 80-95 | tee /proc/irq/*/idpf-eth1*/../smp_affinity_list > /dev/null
