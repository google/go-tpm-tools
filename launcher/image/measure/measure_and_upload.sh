#!/bin/bash

# Measures an OS disk image with measure.sh and uploads the resulting
# reference measurements to GCS.
#
# Usage: measure_and_upload.sh <disk> <channel> <gcs_dest> <hash_alg>...
#   disk:     a local disk.raw path, or a gs:// URL of a .tar.gz holding disk.raw.
#   channel:  the image channel passed to measure.sh (e.g. debug, hardened).
#   gcs_dest: GCS object path without extension. sha256 results are written to
#             <gcs_dest>.json and other algorithms to <gcs_dest>_<alg>.json.
#   hash_alg: one or more of sha256, sha384.

set -euo pipefail

if [[ "$#" -lt 4 ]]; then
  echo "Usage: $0 <disk> <channel> <gcs_dest> <hash_alg>..." >&2
  exit 1
fi

disk="$1"
channel="$2"
gcs_dest="$3"
shift 3

# Steps sharing /workspace run in parallel, so keep files in a unique directory.
work_dir="$(mktemp -d -p "${PWD}")"
trap 'rm -rf "${work_dir}"' EXIT

if [[ "${disk}" == gs://* ]]; then
  # Download only the start of the disk image to save time. The target partition is completely within the first 256 MiB.
  prefix_bytes=$((256 * 1024 * 1024))
  echo "Downloading the first ${prefix_bytes} bytes of disk.raw from ${disk}"
  # Allow gcloud and tar to safely fail with SIGPIPE when head closes the pipe.
  set +o pipefail
  gcloud storage cat "${disk}" | tar -xzO disk.raw | head -c "${prefix_bytes}" > "${work_dir}/disk.raw"
  set -o pipefail
  disk="${work_dir}/disk.raw"
  if [[ "$(stat -c %s "${disk}")" -ne "${prefix_bytes}" ]]; then
    echo "Error: downloaded prefix of ${disk} is shorter than ${prefix_bytes} bytes." >&2
    exit 1
  fi

  # cgpt refuses to parse truncated disk files. Pad the file back to its original size as a sparse file to satisfy its checks.
  alternate_lba="$(od -An -t u8 -j 544 -N 8 "${disk}" | tr -d ' ')"
  truncate -s "$(( (alternate_lba + 1) * 512 ))" "${disk}"

  p12_start="$(cgpt show -i 12 -b -n "${disk}")"
  p12_size="$(cgpt show -i 12 -s -n "${disk}")"
  if (( (p12_start + p12_size) * 512 > prefix_bytes )); then
    echo "Error: partition 12 ends past the downloaded prefix." >&2
    exit 1
  fi
fi

for alg in "$@"; do
  suffix=""
  if [[ "${alg}" != "sha256" ]]; then
    suffix="_${alg}"
  fi
  output="${work_dir}/measure_output${suffix}.json"
  echo "Measuring ${disk} (channel=${channel}, alg=${alg})"
  /usr/local/bin/measure.sh "${disk}" "${output}" "${channel}" x86_64 "${alg}"
  gcloud storage cp "${output}" "${gcs_dest}${suffix}.json"
done
