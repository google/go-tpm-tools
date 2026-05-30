#!/bin/bash
find_interfaces_by_driver() {
  local target_driver="$1"
  local found=()
  for intf in /sys/class/net/*; do
    [[ -e "$intf/device/driver" ]] || continue
    local driver
    driver=$(basename "$(readlink "$intf/device/driver")")
    if [[ "$driver" == "$target_driver" ]]; then
      found+=("$(basename "$intf")")
    fi
  done
  echo "${found[@]}"
}

get_mac() {
  local intf="$1"
  cat "/sys/class/net/${intf}/address" 2>/dev/null
}

get_pci_path() {
  local intf="$1"
  basename "$(readlink "/sys/class/net/${intf}/device" 2>/dev/null)"
}

VIRTIO_INTFS=($(find_interfaces_by_driver "virtio_net"))
VIRTIO_INTF="${VIRTIO_INTFS[0]}"
VIRTIO_MAC=""
if [[ -n "$VIRTIO_INTF" ]]; then
  VIRTIO_MAC=$(get_mac "$VIRTIO_INTF")
fi

IDPF_RAW_INTFS=($(find_interfaces_by_driver "idpf"))

# Pair each IDPF interface with its PCI path for sorting
IDPF_WITH_PCI=()
for intf in "${IDPF_RAW_INTFS[@]}"; do
  pci_path=$(get_pci_path "$intf")
  IDPF_WITH_PCI+=("$pci_path:$intf")
done

# Sort alphabetically by PCI path (primary is always the lower PCI address)
IFS=$'\n' sorted_idpf=($(sort <<<"${IDPF_WITH_PCI[*]}")); unset IFS

PRIMARY_IDPF=""
PRIMARY_MAC=""
SECONDARY_IDPF=""
SECONDARY_MAC=""

if (( ${#sorted_idpf[@]} >= 1 )); then
  PRIMARY_IDPF=$(echo "${sorted_idpf[0]}" | cut -d: -f2)
  PRIMARY_MAC=$(get_mac "$PRIMARY_IDPF")
fi

if (( ${#sorted_idpf[@]} >= 2 )); then
  SECONDARY_IDPF=$(echo "${sorted_idpf[1]}" | cut -d: -f2)
  SECONDARY_MAC=$(get_mac "$SECONDARY_IDPF")
fi

# Save systemd network files
mkdir -p /etc/systemd/network/

# Write Virtio link file matching by MAC
if [[ -n "$VIRTIO_MAC" ]]; then
  cat << EOF > /etc/systemd/network/10-virtio.link
[Match]
MACAddress=$VIRTIO_MAC

[Link]
Name=tap0
EOF
fi

# Write IDPF primary link file matching by MAC
if [[ -n "$PRIMARY_MAC" ]]; then
  cat << EOF > /etc/systemd/network/20-idpf-primary.link
[Match]
MACAddress=$PRIMARY_MAC

[Link]
Name=eth0
EOF
fi

# Write IDPF secondary link file matching by MAC
if [[ -n "$SECONDARY_MAC" ]]; then
  cat << EOF > /etc/systemd/network/20-idpf-secondary.link
[Match]
MACAddress=$SECONDARY_MAC

[Link]
Name=eth1
EOF
fi

# Bring all current interfaces down first to prevent any active name-swapping conflicts
if [[ -n "$VIRTIO_INTF" ]]; then
  ip link set "$VIRTIO_INTF" down 2>/dev/null || true
fi
if [[ -n "$PRIMARY_IDPF" ]]; then
  ip link set "$PRIMARY_IDPF" down 2>/dev/null || true
fi
if [[ -n "$SECONDARY_IDPF" ]]; then
  ip link set "$SECONDARY_IDPF" down 2>/dev/null || true
fi

# Reload udev rules and trigger renaming while they are down
udevadm control --reload-rules
udevadm trigger --subsystem-match=net --action=add

# Wait a brief moment for udev to finish processing the renaming
sleep 2

# Virtio network file
cat << 'EOF' > /etc/systemd/network/10-virtio.network
[Match]
Name=tap0

[Network]
Address=192.168.100.2/24
DHCP=no
LinkLocalAddressing=no
EOF

# Primary GCE interface (eth0) - Higher Priority (Metric 100)
cat << 'EOF' > /etc/systemd/network/20-idpf-primary.network
[Match]
Name=eth0

[Network]
DHCP=yes
IPv6AcceptRA=yes

[DHCPv4]
RouteMetric=100

[DHCPv6]
RouteMetric=100
EOF

# Secondary GCE interface (eth1) - Lower Priority (Metric 200)
cat << 'EOF' > /etc/systemd/network/20-idpf-secondary.network
[Match]
Name=eth1

[Network]
DHCP=yes
IPv6AcceptRA=yes

[DHCPv4]
RouteMetric=200

[DHCPv6]
RouteMetric=200
EOF

# Save post-boot network optimization service to apply settings after
# all network setup and guest agents have finished starting.
cat << 'EOF' > /etc/systemd/system/bc-network-optimization.service
[Unit]
Description=Confidential Space BC Network Optimization
After=systemd-networkd.service google-guest-agent.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/share/oem/confidential_space/bc_network_optimization.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# Restart systemd-networkd to apply the configuration and bring the renamed interfaces up
systemctl restart systemd-networkd

# Save a custom udev rule to apply runtime network optimizations (XPS, NUMA, IRQ affinity)
# on interface add/change events. This ensures optimizations are persistently applied
# whenever the interface state changes or is reset by standard GCE network agents.
# We name it lexically high (99-zz-...) to run after standard GCE udev rules.
mkdir -p /etc/udev/rules.d/
cat << 'EOF' > /etc/udev/rules.d/99-zz-bc-network-optimization.rules
ACTION=="add|change", SUBSYSTEM=="net", KERNEL=="eth[01]", RUN+="/usr/share/oem/confidential_space/bc_network_runtime_optimization.sh"
EOF

# Reload udev rules
udevadm control --reload-rules

# Enable and start the post-boot optimization service to perform one-time settings (ring size, etc.)
systemctl enable bc-network-optimization.service
systemctl start bc-network-optimization.service
