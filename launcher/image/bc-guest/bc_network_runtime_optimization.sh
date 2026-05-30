#!/bin/bash

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

  # Wait for interface to be fully online and stable in systemd-networkd
  systemd-networkd-wait-online -i "$intf" --timeout="$timeout_secs" || true

  # Wait for interface IRQ entries to be fully populated in procfs
  local irq_timeout=20
  while ! ls /proc/irq/*/idpf-${intf}* >/dev/null 2>&1; do
    sleep 0.5
    ((irq_timeout--))
    if ((irq_timeout <= 0)); then
      echo "Timeout waiting for ${intf} IRQ entries to appear" >&2
      break
    fi
  done
}

wait_stable eth0 30
wait_stable eth1 30

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
