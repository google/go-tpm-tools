#!/bin/bash
local OPTIND
set -euxo pipefail

print_usage() {
    echo "usage: test_launcher.sh [-i imageName] [-p projectName] [-m metadata]"
    echo "  -i <imageName>: which image name to use for the VM"
    echo "  -p <imageProject>: which image project to use for the VM"
    echo "  -m <metadata>: metadata variables on VM creation; passed directly into gcloud"
    echo "  -f <metadataFromFile>: read a metadata value from a file; specified in format key=filePath"
    echo "  -n <instanceName>: instance name"
    echo "  -z <instanceZone>: instance zone"
    echo "  -s <subnet>: subnet"
    echo "  -t <stackType>: stack type"
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

  echo 'Creating VM' ${VM_NAME} 'with image' $IMAGE_NAME

  # check the active account
  gcloud auth list

  # Max disk for n2d-standard-2 (8GB memory) at 1% memory overhead.
  MIN_DISK_SIZE=11
  MAX_DISK_SIZE_GB=80
  ADDTL_DISK_RANGE=$(($MAX_DISK_SIZE_GB - $MIN_DISK_SIZE + 1))
  DISK_SIZE_GB=$(($MIN_DISK_SIZE + ($RANDOM % $ADDTL_DISK_RANGE)))

  gcloud compute instances create $VM_NAME --confidential-compute --maintenance-policy=TERMINATE \
    --machine-type=n2d-standard-2 --boot-disk-size=$DISK_SIZE_GB --scopes=cloud-platform --zone $ZONE \
    --image=$IMAGE_NAME --image-project=$PROJECT_NAME --subnet=$SUBNET --shielded-secure-boot $APPEND_METADATA \
    $APPEND_METADATA_FILE  --stack-type=$STACK_TYPE
}

IMAGE_NAME=''
METADATA_FILE=''
METADATA=''
PROJECT_NAME=''
VM_NAME=''
ZONE=''
SUBNET='default'
STACK_TYPE='IPV4_ONLY'

# In getopts, a ':' following a letter means that that flag takes an argument.
# For example, i: means -i takes an additional argument.
while getopts 'i:f:m:p:n:z:s:t:' flag; do
  case "${flag}" in
    i) IMAGE_NAME=${OPTARG} ;;
    f) METADATA_FILE=${OPTARG} ;;
    m) METADATA=${OPTARG} ;;
    p) PROJECT_NAME=${OPTARG} ;;
    n) VM_NAME=${OPTARG} ;;
    z) ZONE=${OPTARG} ;;
    s) SUBNET=${OPTARG} ;;
    t) STACK_TYPE=${OPTARG} ;;
    *) print_usage ;;
  esac
done

create_vm
