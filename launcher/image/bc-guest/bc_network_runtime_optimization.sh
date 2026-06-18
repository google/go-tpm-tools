#!/bin/bash

wait_stable() {
  local intf="$1"
  local timeout_secs="$2"

  # Wait for interface to go down in case it was just reset
  local timeout=$((timeout_secs * 2))
  while [[ "$(cat "/sys/class/net/${intf}/carrier" 2>/dev/null)" == "1" ]]; do
    sleep 0.5
    ((timeout--))
    if ((timeout <= 0)); then break; fi
  done

  # Wait for physical link/carrier to be restored in sysfs
  local timeout=$((timeout_secs * 2)) # Since we sleep 0.5s
  while [[ "$(cat "/sys/class/net/${intf}/carrier" 2>/dev/null)" != "1" ]]; do
    sleep 0.5
    ((timeout--))
    if ((timeout <= 0)); then break; fi
  done

  # Force systemd to wait until it is fully routable (has DHCP)
  /usr/lib/systemd/systemd-networkd-wait-online -i "${intf}:routable" --timeout="$timeout_secs" || true

  # Wait for interface IRQ entries to begin appearing in procfs
  local timeout=$((timeout_secs * 2)) 
  while ! ls /proc/irq/*/idpf-${intf}* >/dev/null 2>&1; do
    sleep 0.5
    ((timeout--))
    if ((timeout <= 0)); then break; fi
  done
  
  # Let the driver finish allocating the remaining queues and applying its internal affinity hints
  sleep 2
}

run_optimize() {
  local intf="$1"
  local node irq_affinity

  # We selected these specific CPU ranges (80, 82, ... for eth0 and 192, 194, ... for eth1)
  # because we want 16 CPUs at the end of the NUMA node (CPUs 0-111 are NUMA node 0 and
  # CPUs 112-223 are NUMA node 1) and we are avoiding the siblings which are adjacent
  # to each other (e.g., 80 is siblings with 81, and 192 is siblings with 193).
  if [[ "$intf" == "eth0" ]]; then
    node=0
    irq_affinity="80,82,84,86,88,90,92,94,96,98,100,102,104,106,108,110"
  elif [[ "$intf" == "eth1" ]]; then
    node=1
    irq_affinity="192,194,196,198,200,202,204,206,208,210,212,214,216,218,220,222"
  else
    return 1
  fi

  wait_stable "${intf}" 10

  # Disable XPS
  echo 0 | tee "/sys/class/net/${intf}/queues/tx*/xps_cpus" 2>/dev/null || true

  # NUMA Node enlightment
  echo "${node}" | tee "/sys/class/net/${intf}/device/numa_node" 2>/dev/null || true

  # IRQ smp affinity optimizations
  echo "${irq_affinity}" | tee /proc/irq/*/idpf-${intf}*/../smp_affinity_list 2>/dev/null || true
}

optimize_interface() {
  local intf="$1"
  # Only start the optimization if the optimization isn't already running for the given interface
  if command -v flock >/dev/null 2>&1; then
    (
      flock -n 9 || exit 0
      run_optimize "${intf}"
    ) 9>"/run/bc-network-opt-${intf}.lock"
  else
    run_optimize "${intf}"
  fi
}

target_intf="$1"
if [[ -z "$target_intf" ]]; then
  optimize_interface eth0
  optimize_interface eth1
elif [[ "$target_intf" == "eth0" || "$target_intf" == "eth1" ]]; then
  optimize_interface "$target_intf"
fi

# Sysctl optimizations
sysctl -w net.core.netdev_budget=600 2>/dev/null || true
sysctl -w net.core.netdev_budget_usecs=4000 2>/dev/null || true
