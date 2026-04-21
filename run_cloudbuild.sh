#!/bin/bash
# Run the script: ./run_cloudbuild.sh
set -euxo pipefail

# Append a timestamp, as there is a check in finish-image-build that checks if
# the image already exists.
IMAGE_SUFFIX="$USER-test-image-`date +%s`"

DIR=$(dirname -- "${BASH_SOURCE[0]}")
echo "Running Cloud Build on directory $DIR"

# If you get the error:
# googleapi: Error 403: Required 'compute.images.get' permission for 'foo', forbidden
#
# Ensure you grant Cloud Build access to Compute Images:
# https://pantheon.corp.google.com/compute/images?referrer=search&tab=exports&project=$PROJECT_ID
gcloud beta builds submit --config=${DIR}/cloudbuild.yaml \
  --substitutions=_OUTPUT_IMAGE_SUFFIX="${IMAGE_SUFFIX}"

echo "Image creation successful."
echo "Create a VM using the debug image confidential-space-debug-${IMAGE_SUFFIX}"
echo "gcloud compute instances create confidential-space-test --image=confidential-space-debug-${IMAGE_SUFFIX} --metadata ..."
echo "Or use the hardened image confidential-space-hardened-${IMAGE_SUFFIX}"
