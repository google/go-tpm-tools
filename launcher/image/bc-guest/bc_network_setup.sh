#!/bin/bash

# Dynamic renaming of the virtio device to tap0 to prevent naming conflicts
for dev in /sys/class/net/*; do
    if [[ -d "$dev/device" && "$(basename "$(readlink "$dev/device/driver")")" == "virtio_net" ]]; then
        VIRTIO_INTERFACE=$(basename "$dev")
        break
    fi
done

if [[ -n "$VIRTIO_INTERFACE" && "$VIRTIO_INTERFACE" != "tap0" ]]; then
    ip link set "$VIRTIO_INTERFACE" down
    ip link set "$VIRTIO_INTERFACE" name tap0
    ip link set tap0 up
fi

mkdir -p /etc/systemd/network/

# Primary GCE interface (eth0) - Higher Priority (Metric 100)
cat << 'EOF' > /etc/systemd/network/10-idpf-primary.network
[Match]
Name=eth0
Driver=idpf

[Network]
DHCP=yes
IPv6AcceptRA=yes

[DHCPv4]
RouteMetric=100

[DHCPv6]
RouteMetric=100
EOF

# Secondary GCE interfaces (eth1, eth2, etc.) - Lower Priority (Metric 200)
cat << 'EOF' > /etc/systemd/network/10-idpf-secondary.network
[Match]
Name=eth[1-9]*
Driver=idpf

[Network]
DHCP=yes
IPv6AcceptRA=yes

[DHCPv4]
RouteMetric=200

[DHCPv6]
RouteMetric=200
EOF

cat << 'EOF' > /etc/systemd/network/10-virtio.link
[Match]
Driver=virtio_net

[Link]
Name=tap0
EOF

cat << 'EOF' > /etc/systemd/network/10-virtio.network
[Match]
Name=tap0

[Network]
Address=192.168.100.2/24
DHCP=no
LinkLocalAddressing=no
EOF
