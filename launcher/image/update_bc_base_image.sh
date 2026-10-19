#!/usr/bin/env bash
#
# Exports base and debug Bowcaster images to Cloud Storage, computes their
# SHA-256 digests, and prints the substitutions for launcher/cloudbuild.yaml.

set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <base-image-name> <debug-image-name>" >&2
  exit 1
fi

BASE_IMAGE="$1"
DEBUG_IMAGE="$2"
PROJECT="confidential-space-images-dev"
BUCKET="${PROJECT}_raw-images"

export_and_hash() {
  local image="$1"
  local tarball="gs://${BUCKET}/${image}.tar.gz"

  echo "==> Exporting ${image} to ${tarball}..." >&2
  gcloud compute images export \
    --project="${PROJECT}" \
    --image-project="${PROJECT}" \
    --image="${image}" \
    --destination-uri="${tarball}" \
    --zone="us-west1-a" >&2

  echo "==> Computing SHA-256 for ${tarball}..." >&2
  gcloud storage cat "${tarball}" | sha256sum | awk '{print $1}'
}

BASE_SHA="$(export_and_hash "${BASE_IMAGE}")"
DEBUG_SHA="$(export_and_hash "${DEBUG_IMAGE}")"

cat <<EOF

Substitutions for launcher/cloudbuild.yaml:

  '_BC_BASE_IMAGE': '${BASE_IMAGE}'
  '_BC_BASE_IMAGE_SHA256': '${BASE_SHA}'
  '_BC_DEBUG_IMAGE': '${DEBUG_IMAGE}'
  '_BC_DEBUG_IMAGE_SHA256': '${DEBUG_SHA}'
EOF
