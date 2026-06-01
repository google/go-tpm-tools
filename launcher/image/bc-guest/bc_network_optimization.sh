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

    log_echo "Waiting for ${intf} to become stable..." > /dev/console

    # Wait for sysfs carrier
    local timeout=$((timeout_secs * 2))
    while [[ "$(cat "/sys/class/net/${intf}/carrier" 2>/dev/null)" != "1" ]]; do
        sleep 0.5
        ((timeout--))
        if ((timeout <= 0)); then break; fi
    done

    # Force systemd to wait until it is fully routable (has DHCP)
    /usr/lib/systemd/systemd-networkd-wait-online -i "${intf}:routable" --timeout="$timeout_secs" || true
    
    # Wait for an IPv4 address
    local ip_timeout=$((timeout_secs * 2))
    while ! ip -4 addr show dev "$intf" | grep -q "inet "; do
        sleep 0.5
        ((ip_timeout--))
        if ((ip_timeout <= 0)); then break; fi
    done
}

wait_reset() {
    local intf="$1"
    local timeout_secs="$2"

    log_echo "Waiting for ${intf} to reset..." > /dev/console
    # 1. Sleep to let the driver actually begin its asynchronous reset and drop carrier/link
    sleep 1.5

    # 2. Wait for carrier to come back UP to 1
    local timeout=$((timeout_secs * 2))
    while [[ "$(cat "/sys/class/net/${intf}/carrier" 2>/dev/null)" != "1" ]]; do
        sleep 0.5
        ((timeout--))
        if ((timeout <= 0)); then 
            log_echo "Warning: timed out waiting for ${intf} carrier to come up" > /dev/console
            break
        fi
    done

    # 3. Wait for systemd-networkd to mark it online/routable (fully configured with DHCP)
    /usr/lib/systemd/systemd-networkd-wait-online -i "${intf}:routable" --timeout="$timeout_secs" || true

    # 4. Extra safety sleep to let idpf driver completely settle all internal queues/mailbox/vport
    sleep 2.5
    log_echo "${intf} reset completed and driver settled." > /dev/console
}

log_echo "Starting network optimizations..." > /dev/console

# --- Configure eth0 ---
wait_stable eth0 10
# Changing combined queue count resets the interface
log_echo "Configuring combined queue count to 16 on eth0..." > /dev/console
ethtool -L eth0 combined 16
wait_reset eth0 10

# Changing ring size resets the interface
log_echo "Configuring ring size to 2048 on eth0..." > /dev/console
ethtool -G eth0 rx 2048 tx 2048 tcp-data-split off
wait_reset eth0 10

log_echo "Configuring coalescing parameters on eth0..." > /dev/console
ethtool -C eth0 adaptive-rx off adaptive-tx off rx-usecs 20 tx-usecs 64

# --- Configure eth1 ---
wait_stable eth1 10
# Changing combined queue count resets the interface
log_echo "Configuring combined queue count to 16 on eth1..." > /dev/console
ethtool -L eth1 combined 16
wait_reset eth1 10

# Changing ring size resets the interface
log_echo "Configuring ring size to 2048 on eth1..." > /dev/console
ethtool -G eth1 rx 2048 tx 2048 tcp-data-split off
wait_reset eth1 10

log_echo "Configuring coalescing parameters on eth1..." > /dev/console
ethtool -C eth1 adaptive-rx off adaptive-tx off rx-usecs 20 tx-usecs 64

# Run runtime optimizations
if [[ -f /usr/share/oem/confidential_space/bc_network_runtime_optimization.sh ]]; then
  /usr/share/oem/confidential_space/bc_network_runtime_optimization.sh
fi

# Enable and start the background network monitor service to dynamically 
# re-apply optimizations on carrier up events
systemctl enable bc-network-monitor.service
systemctl start --no-block bc-network-monitor.service

log_echo "Network optimizations completed." > /dev/console
