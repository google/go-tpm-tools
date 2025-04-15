#!/bin/bash

readonly OEM_PATH='/usr/share/oem'
readonly CS_PATH="${OEM_PATH}/confidential_space"
readonly EXPERIMENTS_BINARY="confidential_space_experiments"
readonly GPU_REF_VALUES_PATH="${CS_PATH}/gpu"
readonly COS_GPU_INSTALLER_IMAGE_REF="${GPU_REF_VALUES_PATH}/cos_gpu_installer_image_ref"
readonly COS_GPU_INSTALLER_IMAGE_DIGEST="${GPU_REF_VALUES_PATH}/cos_gpu_installer_image_digest"

copy_launcher() {
  cp launcher "${CS_PATH}/cs_container_launcher"
}

copy_experiment_client() {
  # DownloadExpBinary creates the file at EXPERIMENTS_BINARY.
  cp $EXPERIMENTS_BINARY "${CS_PATH}/${EXPERIMENTS_BINARY}"
  chmod +x "${CS_PATH}/${EXPERIMENTS_BINARY}"
}

setup_launcher_systemd_unit() {
  cp container-runner.service "${CS_PATH}/container-runner.service"
  cp exit_script.sh "${CS_PATH}/exit_script.sh"
}

append_cmdline() {
  local arg="$1"
  if [[ ! -d /mnt/disks/efi ]]; then
    mkdir /mnt/disks/efi
  fi
  mount /dev/sda12 /mnt/disks/efi
  sed -i -e "s|cros_efi|cros_efi ${arg}|g" /mnt/disks/efi/efi/boot/grub.cfg
  umount /mnt/disks/efi
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
  cp "$1" ${OEM_PATH}/user-data
  touch ${OEM_PATH}/meta-data
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

configure_cloud_logging() {
  # Copy CS-specific fluent-bit config to OEM partition.
  cp fluent-bit-cs.conf "${CS_PATH}"
}

configure_node_problem_detector() {
  # Copy CS-specific node-problem-detector configs to OEM partition.
  cp nodeproblemdetector/system-stats-monitor-cs.json "${CS_PATH}"
  cp nodeproblemdetector/boot-disk-size-consistency-monitor-cs.json "${CS_PATH}"
  cp nodeproblemdetector/docker-monitor-cs.json "${CS_PATH}"
  cp nodeproblemdetector/kernel-monitor-cs.json "${CS_PATH}"
}

configure_systemd_units_for_debug() {
  configure_cloud_logging
  configure_node_problem_detector
}
configure_systemd_units_for_hardened() {
  configure_necessary_systemd_units
  configure_cloud_logging
  configure_node_problem_detector
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
}

get_cos_gpu_installer_image_digest() {
  local image_ref="${1}"
  local registry
  local repo_with_image_name
  local tag
  local manifest_url
  local image_digest

  # Example match: gcr.io/cos-cloud/cos-gpu-installer:v2.4.8
  if [[ "$image_ref" =~ ^([^/]+)/([^:]+):([^:]+)$ ]]; then
    registry="${BASH_REMATCH[1]}"
    repo_with_image_name="${BASH_REMATCH[2]}"
    tag="${BASH_REMATCH[3]}"
  else
    echo "Error: Invalid image reference format: $image_ref" >&2
    return 1
  fi

  manifest_url="https://${registry}/v2/${repo_with_image_name}/manifests/${tag}"
  image_digest=$(curl -s --head ${manifest_url} | grep -i Docker-Content-Digest | cut -d' ' -f2)
  echo "${image_digest}"
}


set_gpu_driver_ref_values() {
  local cos_gpu_installer_image_ref
  local cos_gpu_installer_image_digest

  mkdir ${GPU_REF_VALUES_PATH}
  cos_gpu_installer_image_ref=$(cos-extensions list -- --gpu-installer)
  if [ -z "${cos_gpu_installer_image_ref}" ]; then
    echo "Error: cos-extensions list returned an empty image reference." >&2
    return 1
  fi

  cos_gpu_installer_image_digest=$(get_cos_gpu_installer_image_digest ${cos_gpu_installer_image_ref})
  if [ -z "${cos_gpu_installer_image_ref}" ]; then
    echo "Error: get_cos_gpu_installer_image_digest returned an empty or invalid digest for: ${cos_gpu_installer_image_ref}." >&2
    return 1
  fi

  image_digest_hex_part=$(echo "${cos_gpu_installer_image_digest}" | sed 's/^sha256://' | tr -d '[:space:]')
  # Check for the expected length of the SHA256 digest (64 hex characters)
  if [ ${#image_digest_hex_part} -ne 64 ]; then
    echo "Error: cos_gpu_installer image digest has an unexpected length: ${#image_digest_hex_part}, Expected 64." >&2
    return 1
  fi
  
  echo ${cos_gpu_installer_image_ref} > ${COS_GPU_INSTALLER_IMAGE_REF}
  echo ${cos_gpu_installer_image_digest} > ${COS_GPU_INSTALLER_IMAGE_DIGEST}
}

main() {
  mount -o remount,rw ${OEM_PATH}
  mkdir ${CS_PATH}

  # Install container launcher entrypoint.
  configure_entrypoint "entrypoint.sh"
  # Install experiment client.
  copy_experiment_client
  # Install container launcher.
  copy_launcher
  set_gpu_driver_ref_values
  setup_launcher_systemd_unit
  # Minimum required COS version for 'e': cos-dev-105-17222-0-0.
  # Minimum required COS version for 'm': cos-dev-113-18203-0-0.
  append_cmdline "cos.protected_stateful_partition=m"
  # Increase wait timeout of the protected stateful partition.
  append_cmdline "systemd.default_timeout_start_sec=900s"

  if [[ "${IMAGE_ENV}" == "debug" ]]; then
    configure_systemd_units_for_debug
    append_cmdline "confidential-space.hardened=false"
  elif [[ "${IMAGE_ENV}" == "hardened" ]]; then
    configure_systemd_units_for_hardened
    append_cmdline "confidential-space.hardened=true"
  else
    echo "Unknown image env: ${IMAGE_ENV}." \
         "Only 'debug' and 'hardened' are supported."
    exit 1
  fi

  # Make sure cache is flushed for the OEM partition.
  sync ${OEM_PATH}

  # Remount as read-only to avoid unexpected changes
  mount -o remount,ro ${OEM_PATH}

  # Verify the content before the OEM sealing step.
  ls -lh ${CS_PATH}
  ls -lh ${OEM_PATH}
}

main
