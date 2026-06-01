#!/bin/bash

wait_stable() {
    local intf="$1"
    local timeout_secs="$2"

    # Wait for interface to go down in case it was just reset
    local down_checks=10
    while [[ "$(cat "/sys/class/net/${intf}/carrier" 2>/dev/null)" == "1" ]]; do
        sleep 0.5
        ((down_checks--))
        if ((down_checks <= 0)); then break; fi
    done

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

echo "Starting network optimizations..." > /dev/console

# --- Configure eth0 ---
wait_stable eth0 30
# Changing combined queue count resets the interface
ethtool -L eth0 combined 16
# Changing ring size resets the interface
wait_stable eth0 30
ethtool -G eth0 rx 2048 tx 2048 tcp-data-split off
wait_stable eth0 30
ethtool -C eth0 adaptive-rx off adaptive-tx off rx-usecs 20 tx-usecs 64

# --- Configure eth1 ---
wait_stable eth1 30
# Changing combined queue count resets the interface
ethtool -L eth1 combined 16
wait_stable eth1 30
# Changing ring size resets the interface
ethtool -G eth1 rx 2048 tx 2048 tcp-data-split off
wait_stable eth1 30
ethtool -C eth1 adaptive-rx off adaptive-tx off rx-usecs 20 tx-usecs 64

# Run runtime optimizations
if [[ -f /usr/share/oem/confidential_space/bc_network_runtime_optimization.sh ]]; then
  /usr/share/oem/confidential_space/bc_network_runtime_optimization.sh
fi

# Enable and start the background network monitor service to dynamically 
# re-apply optimizations on carrier up events
systemctl enable bc-network-monitor.service
systemctl start --no-block bc-network-monitor.service

echo "Network optimizations completed." > /dev/console
