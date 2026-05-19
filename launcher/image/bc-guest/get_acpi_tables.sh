#!/bin/bash
set -euo pipefail

# # Check if the user optionally enabled this feature via the kernel command line
# if ! grep -q "enable-acpi-export" /proc/cmdline; then
# # TODO: remove this print line.  we don't need it 
#   echo "=== ACPI Table Serial Export Disabled (enable-acpi-export not present in /proc/cmdline) ===" > /dev/console
#   exit 0
# fi

echo "=== ACPI TABLE SERIAL EXPORT START ===" > /dev/console

# Loop over all top-level binary ACPI tables needed for complete RTMR0 verification
for table_path in /sys/firmware/acpi/tables/*; do
  if [ -f "${table_path}" ]; then
    table_name=$(basename "${table_path}")
    echo "--- BEGIN TABLE: ${table_name} ---" > /dev/console
    base64 "${table_path}" > /dev/console
    echo "--- END TABLE: ${table_name} ---" > /dev/console
  fi
done

echo "=== ACPI TABLE SERIAL EXPORT END ===" > /dev/console
