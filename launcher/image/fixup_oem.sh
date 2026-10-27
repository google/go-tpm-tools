#!/bin/bash

main() {
  if [[ ! -d /mnt/disks/efi ]]; then
    mkdir /mnt/disks/efi
  fi
  # ChromiumOS / COS GPT disk layout uses partition 12 for the EFI System
  # Partition (https://chromium.googlesource.com/chromiumos/docs/+/HEAD/disk_format.md).
  mount "$(rootdev -s -d)12" /mnt/disks/efi
  sed -i -e 's|systemd.mask=usr-share-oem.mount||g' /mnt/disks/efi/efi/boot/grub.cfg

  # TODO: Remove this fix once the upstream customizer fixed the bug.
  # Fix a string manipulation bug in the dm part of the kernel cmd.
  if grep -q "dm-m2d" /mnt/disks/efi/efi/boot/grub.cfg; then
    sed -i -e 's|dm-m2d|dm-mod|g' /mnt/disks/efi/efi/boot/grub.cfg
    sed -i -e 's|,oemroot|;oemroot|g' /mnt/disks/efi/efi/boot/grub.cfg
  fi

  # Print grub.cfg's kernel command line.
  grep -i '^\s*linux' /mnt/disks/efi/efi/boot/grub.cfg | \
    sed -e 's|.*|[BEGIN_CS_GRUB_CMDLINE]&[END_CS_GRUB_CMDLINE]|g'

  # Convert grub.cfg's kernel command line into what GRUB passes to the kernel.
  local converted_cmdlines
  converted_cmdlines=$(grep -i '^\s*linux' /mnt/disks/efi/efi/boot/grub.cfg | \
    sed -e "s|'ds=nocloud;s=/usr/share/oem/'|ds=nocloud;s=/usr/share/oem/|g" | \
    sed -e 's|\\"|"|g' | \
    sed -e 's|dm-mod.create="|"dm-mod.create=|g' | \
    sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

  local exit_code=0
  while IFS= read -r line; do
    if [[ -z "${line}" ]]; then
      continue
    fi
    echo "[BEGIN_CS_CMDLINE]${line}[END_CS_CMDLINE]"
    local args
    args=$(echo "${line}" | cut -d' ' -f2-)
    local len=${#args}
    echo "Cmdline length: ${len}"
    if (( len > 2047 )); then
      echo "ERROR: Kernel cmdline length (${len}) exceeds 2047 characters limit! Additional arguments may get ignored" >&2
      echo "cmdline: ${args}" >&2
      exit_code=1
    fi
  done <<< "${converted_cmdlines}"

  if (( exit_code != 0 )); then
    umount /mnt/disks/efi
    exit ${exit_code}
  fi

  umount /mnt/disks/efi

  # Now the oem partition is sealed, we mount it to print it's content
  if [[ ! -d /mnt/disks/oem ]]; then
    mkdir /mnt/disks/oem
  fi

  # Since it's sealed, we mount it read-only to prevent changes
  # ChromiumOS / COS GPT disk layout uses partition 8 for the OEM partition
  # (https://chromium.googlesource.com/chromiumos/docs/+/HEAD/disk_format.md).
  mount -o ro "$(rootdev -s -d)8" /mnt/disks/oem
  ls -l /mnt/disks/oem/
  ls -l /mnt/disks/oem/confidential_space

  umount /mnt/disks/oem
}

main
