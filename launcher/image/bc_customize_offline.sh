#!/bin/bash
set -exuo pipefail

readonly RAW_IMAGE_PATH="${RAW_IMAGE_PATH:-/workspace/disk.raw}"
readonly WORK_DIR="${WORK_DIR:-/workspace/launcher/image}"
readonly IMAGE_ENV_VALUE="${IMAGE_ENV:-hardened}"

cleanup() {
  set +e
  if mountpoint -q /mnt/disks/efi; then
    umount /mnt/disks/efi
  fi
  if mountpoint -q /mnt/disks/oem; then
    umount /mnt/disks/oem
  fi
  if [[ -n "${LOOP_DEVICE:-}" ]]; then
    losetup -d "${LOOP_DEVICE}"
  fi
}

main() {
  trap cleanup EXIT

  if [[ ! -f "${RAW_IMAGE_PATH}" ]]; then
    echo "Missing raw image: ${RAW_IMAGE_PATH}"
    exit 1
  fi

  LOOP_DEVICE=$(losetup --show -fP "${RAW_IMAGE_PATH}")
  EFI_PARTITION="${LOOP_DEVICE}p12"
  OEM_PARTITION="${LOOP_DEVICE}p8"

  if [[ ! -b "${EFI_PARTITION}" || ! -b "${OEM_PARTITION}" ]]; then
    echo "Expected loop partitions not found for ${LOOP_DEVICE}"
    lsblk "${LOOP_DEVICE}" || true
    exit 1
  fi

  mkdir -p /mnt/disks/efi /mnt/disks/oem
  mount "${OEM_PARTITION}" /mnt/disks/oem

  pushd "${WORK_DIR}"
  EFI_PARTITION="${EFI_PARTITION}" \
  OEM_PATH="/mnt/disks/oem" \
  RUNTIME_OEM_PATH="/usr/share/oem" \
  IMAGE_ENV="${IMAGE_ENV_VALUE}" \
  ./bcpreload.sh

  umount /mnt/disks/oem

  EFI_PARTITION="${EFI_PARTITION}" \
  OEM_PARTITION="${OEM_PARTITION}" \
  ./fixup_oem.sh
  popd

  sync
}

main