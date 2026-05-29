#!/bin/bash

# Wait for the early-boot optimization service to complete (timeout up to 30s)
TIMEOUT=30
while [[ -f /tmp/bc_network_optimizing ]]; do
  sleep 1
  ((TIMEOUT--))
  if ((TIMEOUT <= 0)); then
    echo "Timeout waiting for bc_network_optimizing to complete. Exiting." >&2
    exit 1
  fi
done

# Wait for interfaces to be online and their IRQ entries to be fully populated in procfs
if [[ -d /sys/class/net/eth0 ]]; then
  systemd-networkd-wait-online -i eth0 --timeout=15 || true
  
  # Wait for eth0 IRQs to appear
  IRQ_TIMEOUT=20
  while ! ls /proc/irq/*/idpf-eth0* >/dev/null 2>&1; do
    sleep 0.5
    ((IRQ_TIMEOUT--))
    if ((IRQ_TIMEOUT <= 0)); then
      echo "Timeout waiting for eth0 IRQ entries to appear" >&2
      break
    fi
  done
fi

if [[ -d /sys/class/net/eth1 ]]; then
  systemd-networkd-wait-online -i eth1 --timeout=15 || true
  
  # Wait for eth1 IRQs to appear
  IRQ_TIMEOUT=20
  while ! ls /proc/irq/*/idpf-eth1* >/dev/null 2>&1; do
    sleep 0.5
    ((IRQ_TIMEOUT--))
    if ((IRQ_TIMEOUT <= 0)); then
      echo "Timeout waiting for eth1 IRQ entries to appear" >&2
      break
    fi
  done
fi

# Sleep briefly to ensure the driver/kernel default affinity assignments have completed
sleep 1

# Disable XPS
echo 0 | tee /sys/class/net/eth0/queues/tx*/xps_cpus 2>/dev/null || true
echo 0 | tee /sys/class/net/eth1/queues/tx*/xps_cpus 2>/dev/null || true

# NUMA Node enlightment
echo 0 | tee /sys/class/net/eth0/device/numa_node 2>/dev/null || true
echo 1 | tee /sys/class/net/eth1/device/numa_node 2>/dev/null || true

# IRQ smp affinity optimizations
echo 40-55 | tee /proc/irq/*/idpf-eth0*/../smp_affinity_list 2>/dev/null || true
echo 96-111 | tee /proc/irq/*/idpf-eth1*/../smp_affinity_list 2>/dev/null || true

# Sysctl optimizations
sysctl -w net.core.netdev_budget=600 2>/dev/null || true
sysctl -w net.core.netdev_budget_usecs=4000 2>/dev/null || true
