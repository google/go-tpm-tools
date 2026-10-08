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
  echo "Downloading ${disk}"
  gcloud storage cat "${disk}" | tar -xz -C "${work_dir}" disk.raw
  disk="${work_dir}/disk.raw"
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
