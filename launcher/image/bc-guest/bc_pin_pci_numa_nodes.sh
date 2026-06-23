#!/bin/bash
set -euo pipefail

# This script configures the NUMA node for GPUs, NICs, and Bridges attached to the VM.
# It also unbinds and rebinds the drivers for any devices that are already bound,
# ensuring the drivers allocate their memory buffers on the correct NUMA node.

configure_devices() {
  local device_type="$1"
  local target_nodes_str="$2"
  shift 2
  local addrs=("$@")

  # Convert target nodes string to an array.
  local target_nodes=(${target_nodes_str})
  local expected_count=${#target_nodes[@]}

  # Validate device count
  local num_devs=${#addrs[@]}
  if [[ "${num_devs}" -ne "${expected_count}" ]]; then
    echo "Error: Expected exactly ${expected_count} ${device_type} devices, found ${num_devs}." > /dev/console
    return 1
  fi

  # Sort PCI addresses to ensure consistent mapping.
  IFS=$'\n' sorted_addrs=($(sort <<<"${addrs[*]}"))
  unset IFS

  echo "Found exactly ${expected_count} ${device_type} devices. Mapping to NUMA nodes: ${target_nodes_str}." > /dev/console

  for i in "${!sorted_addrs[@]}"; do
    local pci_addr="${sorted_addrs[i]}"
    local target_node="${target_nodes[i]}"

    echo "Configuring ${device_type} ${pci_addr}: setting NUMA node to ${target_node}..." > /dev/console

    # Write the target NUMA node to sysfs.
    echo "${target_node}" | tee "/sys/bus/pci/devices/${pci_addr}/numa_node" > /dev/null || true

    # Check if the device is currently bound to a driver.
    local driver_link="/sys/bus/pci/devices/${pci_addr}/driver"
    if [[ -L "${driver_link}" ]]; then
      local driver_path
      driver_path=$(readlink "${driver_link}")
      local driver_name
      driver_name=$(basename "${driver_path}")

      echo "Rebinding driver ${driver_name} for ${device_type} ${pci_addr}..." > /dev/console

      # Unbind device from driver
      echo "${pci_addr}" | tee "/sys/bus/pci/drivers/${driver_name}/unbind" 
      sleep 1

      # Bind device to driver
      echo "${pci_addr}" | tee "/sys/bus/pci/drivers/${driver_name}/bind" > /dev/null || true
      sleep 1

      # For NICs, configure the MTU.
      if [[ "${device_type}" == "NIC" ]]; then
        local interface_name
        interface_name=$(ls "/sys/bus/pci/devices/${pci_addr}/net" 2>/dev/null | head -n 1)

        if [[ -n "${interface_name}" ]]; then
          # The sorted index 'i' corresponds to the GCE network interface index (0, 1, etc.)
          local network_mtu
          # Only query the GCE metadata server for the MTU if it's a debug image,
          # otherwise hard code to 8896.
          if grep -q "confidential-space.hardened=false" /proc/cmdline; then
            echo "Querying GCE metadata for MTU of NIC ${interface_name} (index ${i})..." > /dev/console
            network_mtu=$(curl -s -f -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/${i}/mtu" || echo "")
          else
            network_mtu="8896"
          fi

          if [[ -n "${network_mtu}" ]]; then
            if [[ "${network_mtu}" =~ ^[0-9]+$ ]] && (( network_mtu >= 0 && network_mtu <= 9999 )); then
              echo "Setting MTU for NIC ${interface_name} to ${network_mtu}..." > /dev/console
              ip link set "${interface_name}" mtu "${network_mtu}" || true
            else
              echo "Warning: Invalid MTU value '${network_mtu}' received for NIC ${interface_name}. Must be a number between 0 and 9999." > /dev/console
            fi
          fi
        else
          echo "Warning: Could not find network interface name for PCI address ${pci_addr}" > /dev/console
        fi
      fi
    else
      echo "${device_type} ${pci_addr} is not currently bound to any driver." > /dev/console
    fi
  done
}

main() {
  local gpu_pci_addrs=()
  local nic_pci_addrs=()
  local bridge_pci_addrs=()

  # Find and categorize PCI devices.
  # GPUs: Vendor 0x10de, Device 0x2901
  # NICs: Vendor 0x8086, Device 0x1452
  # Bridges: Vendor 0x15b3, Device 0x1021, Class starting with 0x0207
  for dev_path in /sys/bus/pci/devices/*; do
    if [[ -f "${dev_path}/vendor" && -f "${dev_path}/device" && -f "${dev_path}/class" ]]; then
      local vendor
      vendor=$(cat "${dev_path}/vendor")

      local device
      device=$(cat "${dev_path}/device")

      local class
      class=$(cat "${dev_path}/class")

      if [[ "${vendor}" == "0x10de" && "${device}" == "0x2901" ]]; then
        gpu_pci_addrs+=("$(basename "${dev_path}")")
      elif [[ "${vendor}" == "0x8086" && "${device}" == "0x1452" ]]; then
        nic_pci_addrs+=("$(basename "${dev_path}")")
      elif [[ "${vendor}" == "0x15b3" && "${device}" == "0x1021" && "${class}" == 0x0207* ]]; then
        bridge_pci_addrs+=("$(basename "${dev_path}")")
      fi
    fi
  done

  configure_devices "NIC" "0 1" "${nic_pci_addrs[@]}"
  configure_devices "GPU" "0 0 0 0 1 1 1 1" "${gpu_pci_addrs[@]}"
  configure_devices "Bridge" "0 0 0 0" "${bridge_pci_addrs[@]}"
}

main "$@"
