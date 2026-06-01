#!/bin/bash

log_echo() {
  local btime
  btime=$(awk '/btime/{print $2}' /proc/stat 2>/dev/null || echo 0)
  local current
  current=$(date +%s.%N 2>/dev/null || echo 0)
  local ts
  ts=$(awk -v btime="$btime" -v current="$current" 'BEGIN {printf "[%12.6f]", current - btime}' 2>/dev/null || echo "[   0.000000]")
  echo "$ts $*"
}

wait_stable() {
  local intf="$1"
  local timeout_secs="$2"

  log_echo "Waiting for ${intf} to become stable for runtime optimizations..." > /dev/console

  # Wait for physical link/carrier to be active
  local timeout=$((timeout_secs * 2))
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
  
  sleep 1.5
}

run_optimize() {
  local intf="$1"
  local node irq_affinity

  if [[ "$intf" == "eth0" ]]; then
    node=0
    irq_affinity="40-55"
  elif [[ "$intf" == "eth1" ]]; then
    node=1
    irq_affinity="96-111"
  else
    return 1
  fi

  wait_stable "${intf}" 10

  log_echo "Applying runtime optimizations to ${intf}..." > /dev/console

  # Disable XPS
  log_echo "Disabling XPS on ${intf}..." > /dev/console
  echo 0 | tee "/sys/class/net/${intf}/queues/tx*/xps_cpus" 2>/dev/null || true

  # NUMA Node enlightment
  log_echo "Setting NUMA node of ${intf} to ${node}..." > /dev/console
  echo "${node}" | tee "/sys/class/net/${intf}/device/numa_node" 2>/dev/null || true

  # IRQ smp affinity optimizations
  log_echo "Configuring smp affinity for ${intf} to IRQs ${irq_affinity}..." > /dev/console
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
log_echo "Applying core netdev budget sysctls..." > /dev/console
sysctl -w net.core.netdev_budget=600 2>/dev/null || true
sysctl -w net.core.netdev_budget_usecs=4000 2>/dev/null || true
