#!/bin/bash
set -euxo pipefail

print_usage() {
    echo "usage: test_launcher.sh [-i imageName] [-p projectName] [-m metadata]"
    echo "  -i <imageName>: which image name to use for the VM"
    echo "  -p <imageProject>: which image project to use for the VM"
    echo "  -m <metadata>: metadata variables on VM creation; passed directly into gcloud"
    echo "  -f <metadataFromFile>: read a metadata value from a file; specified in format key=filePath"
    exit 1
}

create_vm() {
  if [ -z "$IMAGE_NAME" ]; then
    echo "Empty image name supplied."
    exit 1
  fi

  APPEND_METADATA=''
  if ! [ -z "$METADATA" ]; then
    APPEND_METADATA="--metadata ${METADATA}"
  fi

  APPEND_METADATA_FILE=''
  if ! [ -z "$METADATA_FILE" ]; then
    APPEND_METADATA_FILE="--metadata-from-file ${METADATA_FILE}"
  fi

  VM_NAME=confidential-space-test-$BUILD_ID
  echo 'Creating VM' ${VM_NAME} 'with image' $IMAGE_NAME

  # check the active account
  gcloud auth list

  gcloud compute instances create $VM_NAME --zone us-central1-a --image=$IMAGE_NAME --image-project=$PROJECT_NAME --shielded-secure-boot \
  $APPEND_METADATA $APPEND_METADATA_FILE
}

IMAGE_NAME=''
PROJECT_NAME=''
VM_NAME=''
METADATA=''
METADATA_FILE=''

# In getopts, a ':' following a letter means that that flag takes an argument.
# For example, i: means -i takes an additional argument.
while getopts 'i:f:m:p:' flag; do
  case "${flag}" in
    i) IMAGE_NAME=${OPTARG} ;;
    f) METADATA_FILE=${OPTARG} ;;
    m) METADATA=${OPTARG} ;;
    p) PROJECT_NAME=${OPTARG} ;;
    *) print_usage ;;
  esac
done

create_vm

# Persist VM name
echo $VM_NAME > /workspace/vm_name.txt
