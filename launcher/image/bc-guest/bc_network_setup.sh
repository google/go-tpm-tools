#!/bin/bash
# Blah
mkdir -p /etc/systemd/network/

cat << 'EOF' > /etc/systemd/network/10-idpf.network
[Match]
Driver=idpf

[Network]
DHCP=yes
IPv6AcceptRA=yes

[DHCPv4]
RouteMetric=100

[DHCPv6]
RouteMetric=100
EOF

cat << 'EOF' > /etc/systemd/network/10-virtio.network
[Match]
Driver=virtio_net

[Network]
Address=192.168.100.2/24
EOF
