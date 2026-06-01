#!/bin/bash

# Bind-mount /bin/true over the google_set_multiqueue to disable it and prevent random resets to XPS
if [[ -f /usr/bin/google_set_multiqueue ]]; then
  echo "Disabling /usr/bin/google_set_multiqueue via bind mount" > /dev/console
  mount --bind /bin/true /usr/bin/google_set_multiqueue || true
fi

# Save systemd network files
mkdir -p /etc/systemd/network/

# Virtio link file to dynamically rename the virtio device to tap0
cat << 'EOF' > /etc/systemd/network/10-virtio.link
[Match]
Driver=virtio_net

[Link]
Name=tap0
EOF

# Virtio network file (lexically ordered before idpf files)
cat << 'EOF' > /etc/systemd/network/10-virtio.network
[Match]
Driver=virtio_net

[Network]
Address=192.168.100.2/24
DHCP=no
LinkLocalAddressing=no
EOF

# Primary GCE interface (eth0) - Higher Priority (Metric 100)
cat << 'EOF' > /etc/systemd/network/20-idpf-primary.network
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
cat << 'EOF' > /etc/systemd/network/20-idpf-secondary.network
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

# Find the virtio interface and bring it down so systemd-udevd can rename it
VIRTIO_INTERFACE=$(basename "$(ls -l /sys/class/net/*/device/driver 2>/dev/null | grep 'virtio_net' | awk '{print $9}' | cut -d/ -f5)")
if [[ -n "$VIRTIO_INTERFACE" && "$VIRTIO_INTERFACE" != "tap0" ]]; then
    ip link set "$VIRTIO_INTERFACE" down
    udevadm control --reload-rules
    udevadm trigger --subsystem-match=net --action=add
fi

# Save post-boot network optimization service to apply settings after
# all network setup and guest agents have finished starting.
cat << 'EOF' > /etc/systemd/system/bc-network-optimization.service
[Unit]
Description=Confidential Space BC Network Optimization
After=systemd-networkd.service google-guest-agent.service network-online.target
Wants=network-online.target

After=network-online.target cloud-final.service google-guest-agent.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/share/oem/confidential_space/bc_network_optimization.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# Save background network monitor service to dynamically re-apply optimizations on carrier up events.
cat << 'EOF' > /etc/systemd/system/bc-network-monitor.service
[Unit]
Description=Confidential Space BC Network Monitor
After=bc-network-optimization.service
Wants=bc-network-optimization.service

[Service]
Type=simple
ExecStart=/usr/share/oem/confidential_space/bc_network_monitor.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Restart systemd-networkd to apply the configuration
systemctl restart systemd-networkd

# Reload systemd to recognize the newly created .service files
systemctl daemon-reload

# Start the network optimization service asynchronously in the background
systemctl enable bc-network-optimization.service
systemctl start --no-block bc-network-optimization.service

