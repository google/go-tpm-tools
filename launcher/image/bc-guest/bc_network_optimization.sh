#!/bin/bash

wait_stable() {
    local intf="$1"
    local timeout_secs="$2"

    # Wait for interface to go down if it was just reset
    sleep 1

    # Wait for sysfs carrier
    local timeout=$((timeout_secs * 2))
    while [[ "$(cat "/sys/class/net/${intf}/carrier" 2>/dev/null)" != "1" ]]; do
        sleep 0.5
        ((timeout--))
        if ((timeout <= 0)); then break; fi
    done

    # Force systemd to wait until it is fully routable (has DHCP)
    systemd-networkd-wait-online -i "${intf}:routable" --timeout="$timeout_secs" || true
    
    # Wait for an IPv4 address
    local ip_timeout=$((timeout_secs * 2))
    while ! ip -4 addr show dev "$intf" | grep -q "inet "; do
        sleep 0.5
        ((ip_timeout--))
        if ((ip_timeout <= 0)); then break; fi
    done
}

# --- Configure eth0 ---
wait_stable eth0 30
# Note: changing ring size resets the interface
ethtool -G eth0 rx 2048 tx 2048 tcp-data-split off
wait_stable eth0 30
ethtool -C eth0 adaptive-rx off adaptive-tx off rx-usecs 20 tx-usecs 64

# --- Configure eth1 ---
wait_stable eth1 30
# Note: changing ring size resets the interface
ethtool -G eth1 rx 2048 tx 2048 tcp-data-split off
wait_stable eth1 30
ethtool -C eth1 adaptive-rx off adaptive-tx off rx-usecs 20 tx-usecs 64

# Run runtime optimizations
if [[ -f /usr/share/oem/confidential_space/bc_network_runtime_optimization.sh ]]; then
  /usr/share/oem/confidential_space/bc_network_runtime_optimization.sh
fi

# Save a custom udev rule to apply runtime network optimizations (XPS, NUMA, IRQ affinity)
# on interface add/change events. This ensures optimizations are persistently applied
# whenever the interface state changes or is reset by standard GCE network agents.
# We name it lexically high (99-zz-...) to run after standard GCE udev rules.
cat << 'EOF' > /etc/udev/rules.d/99-zz-bc-network-optimization.rules
ACTION=="add|change", \
SUBSYSTEM=="net", \
KERNEL=="eth[01]", \
RUN+="/usr/bin/systemd-run --no-block --unit=bc-net-opt-%k /usr/share/oem/confidential_space/bc_network_runtime_optimization.sh"
EOF



# Reload udev rules
udevadm control --reload-rules