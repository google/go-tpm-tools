#!/bin/bash

GRUB_FILE="$1"

readonly OEM_PATH='/usr/share/oem'
readonly CS_PATH="${OEM_PATH}/confidential_space"

append_cmdline() {
  local arg="$1"
  sed -i -e "s|cros_efi|cros_efi ${arg}|g" "${GRUB_FILE}"
}

set_default_boot_target() {
  append_cmdline "systemd.unit=$1"
}

disable_unit() {
  append_cmdline "systemd.mask=$1"
}

enable_unit() {
  append_cmdline "systemd.wants=$1"
}

configure_entrypoint() {
  append_cmdline "'ds=nocloud;s=${OEM_PATH}/'"
}

configure_necessary_systemd_units() {
  # Include basic services.
  enable_unit "basic.target"

  # gcr-wait-online.service is WantedBy=gcr-online.target.
  # The hostname gcr.io does not resolve until systemd-resolved is enabled.
  enable_unit "systemd-resolved.service"

  # Dependencies of container-runner.service.
  enable_unit "network-online.target"
  enable_unit "gcr-online.target"

}

configure_systemd_units_for_hardened() {
  configure_necessary_systemd_units
  # Make entrypoint (via cloud-init) the default unit.
  set_default_boot_target "cloud-final.service"

  disable_unit "var-lib-docker.mount"
  disable_unit "docker.service"
  disable_unit "google-guest-agent.service"
  disable_unit "google-osconfig-init.service"
  disable_unit "google-osconfig-agent.service"
  disable_unit "google-startup-scripts.service"
  disable_unit "google-shutdown-scripts.service"
  disable_unit "konlet-startup.service"
  disable_unit "crash-reporter.service"
  disable_unit "device_policy_manager.service"
  disable_unit "docker-events-collector-fluent-bit.service"
  disable_unit "sshd.service"
  disable_unit "var-lib-toolbox.mount"
  disable_unit "update-engine.service"
}

configure_systemd_units_for_debug() {
  disable_unit "konlet-startup.service"
  disable_unit "update-engine.service"
}

fix_oem() {
  sed -i -e 's|systemd.mask=usr-share-oem.mount||g' "${GRUB_FILE}"

  # TODO: Remove this fix once the upstream customizer fixed the bug.
  # Fix a string manipulation bug in the dm part of the kernel cmd.
  if grep -q "dm-m2d" "${GRUB_FILE}"; then
    sed -i -e 's|dm-m2d|dm-mod|g' "${GRUB_FILE}"
    sed -i -e 's|,oemroot|;oemroot|g' "${GRUB_FILE}"
  fi

  # Print grub.cfg's kernel command line.
  grep -i '^\s*linux' "${GRUB_FILE}" | \
    sed -e 's|.*|[BEGIN_CS_GRUB_CMDLINE]&[END_CS_GRUB_CMDLINE]|g'

  # Convert grub.cfg's kernel command line into what GRUB passes to the kernel.
  grep -i '^\s*linux' "${GRUB_FILE}" | \
    sed -e "s|'ds=nocloud;s=/usr/share/oem/'|ds=nocloud;s=/usr/share/oem/|g" | \
    sed -e 's|\\"|"|g' | \
    sed -e 's|dm-mod.create="|"dm-mod.create=|g' | \
    sed -e 's|.*|[BEGIN_CS_CMDLINE]&[END_CS_CMDLINE]|g'
}

main() {
  configure_entrypoint
  append_cmdline "cos.protected_stateful_partition=m"
  append_cmdline "systemd.default_timeout_start_sec=900s"
  if [[ "${IMAGE_ENV}" == "debug" ]]; then
    configure_systemd_units_for_debug
    append_cmdline "confidential-space.hardened=false"
  elif [[ "${IMAGE_ENV}" == "hardened" ]]; then
    configure_systemd_units_for_hardened
    append_cmdline "confidential-space.hardened=true"
  fi
  fix_oem
}

main