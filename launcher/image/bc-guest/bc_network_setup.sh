#!/bin/bash
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

cat << 'EOF' > /etc/systemd/network/10-virtio.network
[Match]
Driver=virtio_net

[Network]
Address=192.168.100.2/24
DHCP=no
LinkLocalAddressing=no
EOF
