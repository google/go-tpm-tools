#!/bin/bash

wait_stable() {
  local intf="$1"
  local timeout_secs="$2"

  # Wait for interface to go down if it was just reset
  sleep 1

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

  # Force systemd to wait until it is fully routable (has DHCP)
  systemd-networkd-wait-online -i "${intf}:routable" --timeout="$timeout_secs" || true

  # Wait for interface IRQ entries to begin appearing in procfs
  local timeout=$((timeout_secs * 2)) 
  while ! ls /proc/irq/*/idpf-${intf}* >/dev/null 2>&1; do
    sleep 0.5
    ((timeout--))
    if ((timeout <= 0)); then
      echo "Timeout waiting for ${intf} IRQ entries to appear" >&2
      break
    fi
  done
  
  # Let the driver finish allocating the remaining queues and applying its internal affinity hints
  sleep 2
}

echo "Network runtime optimizations starting" > /dev/console

echo "wait for eth0 to stabilize - i" > /dev/console
wait_stable eth0 30

echo "wait for eth1 to stabilize - j" > /dev/console
wait_stable eth1 30

# Disable XPS
echo "disable XPS on eth0 - k" > /dev/console
echo 0 | tee /sys/class/net/eth0/queues/tx*/xps_cpus 2>/dev/null || true
echo "disable XPS on eth1 - l" > /dev/console
echo 0 | tee /sys/class/net/eth1/queues/tx*/xps_cpus 2>/dev/null || true

# NUMA Node enlightment
echo "numa node enlightment on eth0 - m" > /dev/console
echo 0 | tee /sys/class/net/eth0/device/numa_node 2>/dev/null || true
echo "numa node enlightment on eth1 - n" > /dev/console
echo 1 | tee /sys/class/net/eth1/device/numa_node 2>/dev/null || true

# IRQ smp affinity optimizations
echo "IRQ smp affinity optimizations on eth0 - o" > /dev/console
echo 40-55 | tee /proc/irq/*/idpf-eth0*/../smp_affinity_list 2>/dev/null || true
echo "IRQ smp affinity optimizations on eth1 - p" > /dev/console
echo 96-111 | tee /proc/irq/*/idpf-eth1*/../smp_affinity_list 2>/dev/null || true

# Sysctl optimizations
echo "Sysctl optimizations" > /dev/console
sysctl -w net.core.netdev_budget=600 2>/dev/null || true
sysctl -w net.core.netdev_budget_usecs=4000 2>/dev/null || true

echo "Network runtime optimizations complete" > /dev/console