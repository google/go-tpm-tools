#!/bin/bash
# Run script using run_cloudbuild.sh <image-type: debug, hardened>
#
set -euxo pipefail

if [ $# -eq 0 ]; then
  echo "No arguments supplied. Run with image-type."
  exit 1
elif [[ "$1" != "hardened" && "$1" != "debug" ]]; then
  echo "Incorrect args: image-type must be one of debug|hardened"
  exit 1
fi

# Append a timestamp, as there is a check in finish-image-build that checks if
# the image already exists.
IMAGE_SUFFIX="$1-$USER-test-image-`date +%s`"
BUCKET_NAME="$USER-confidential-space-test-images"

DIR=$(dirname -- "${BASH_SOURCE[0]}")
echo "Running Cloud Build on directory $DIR"

# If you get the error:
# googleapi: Error 403: Required 'compute.images.get' permission for 'foo', forbidden
#
# Ensure you grant Cloud Build access to Compute Images:
# https://pantheon.corp.google.com/compute/images?referrer=search&tab=exports&project=$PROJECT_ID
gcloud beta builds submit --config=$DIR/cloudbuild.yaml \
  --substitutions=_OUTPUT_IMAGE_SUFFIX="$IMAGE_SUFFIX",_BUCKET_NAME="$BUCKET_NAME",_IMAGE_ENV="$1"

echo "Image creation successful."
echo "Create a VM using:"
echo "gcloud compute instances create confidential-space-test --image=confidential-space-$IMAGE_SUFFIX"
