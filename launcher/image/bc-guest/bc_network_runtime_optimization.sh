#!/bin/bash

# Disable XPS
echo 0 | tee /sys/class/net/eth0/queues/tx*/xps_cpus 2>/dev/null || true
echo 0 | tee /sys/class/net/eth1/queues/tx*/xps_cpus 2>/dev/null || true

# NUMA Node enlightment
echo 0 | tee /sys/class/net/eth0/device/numa_node 2>/dev/null || true
echo 1 | tee /sys/class/net/eth1/device/numa_node 2>/dev/null || true

# IRQ smp affinity optimizations
echo 40-55 | tee /proc/irq/*/idpf-eth0*/../smp_affinity_list 2>/dev/null || true
echo 96-111 | tee /proc/irq/*/idpf-eth1*/../smp_affinity_list 2>/dev/null || true
