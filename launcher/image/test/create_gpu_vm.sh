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
    echo "  -v <machineType>: type of machine for VM"
    echo "  -g <gpuType>: type of GPU to use for the VM"
    echo "  -c <gpuCount>: number of GPU(s) to use for the VM"
    echo "  -x <confidentialComputeType> : type of Confidential Compute technology. default is NONE"
    exit 1
}

create_vm() {
  if [ -z "$IMAGE_NAME" ]; then
    echo "Empty image name supplied."
    exit 1
  fi

  if [ -z "$GPU_TYPE" ]; then
    echo "Empty gpu type supplied."
    exit 1
  fi

  if [ -z "$GPU_COUNT" ]; then
    echo "Empty gpu count supplied."
    exit 1
  fi

  if [ -z "$MACHINE_TYPE" ]; then
    echo "Empty machine type supplied."
    exit 1
  fi

  CONFIDENTIAL_COMPUTE_FLAGS=""
  if [ "$CONFIDENTIAL_COMPUTE_TYPE" != "NONE" ]; then
    CONFIDENTIAL_COMPUTE_FLAGS="--confidential-compute-type=${CONFIDENTIAL_COMPUTE_TYPE}"
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

  gcloud compute instances create $VM_NAME \
    --maintenance-policy=TERMINATE \
    --machine-type=$MACHINE_TYPE \
    --boot-disk-size=$DISK_SIZE_GB \
    --accelerator=count=$GPU_COUNT,type=$GPU_TYPE \
    --scopes=cloud-platform \
    --zone=$ZONE \
    --image=$IMAGE_NAME \
    --image-project=$PROJECT_NAME \
    --shielded-secure-boot \
    --preemptible \
    $CONFIDENTIAL_COMPUTE_FLAGS \
    $APPEND_METADATA \
    $APPEND_METADATA_FILE
}

IMAGE_NAME=''
METADATA_FILE=''
METADATA=''
PROJECT_NAME=''
VM_NAME=''
ZONE=''
MACHINE_TYPE=''
GPU_TYPE=''
GPU_COUNT=''
DISK_SIZE_GB=100
CONFIDENTIAL_COMPUTE_TYPE='NONE'


# In getopts, a ':' following a letter means that that flag takes an argument.
# For example, i: means -i takes an additional argument.
while getopts 'i:f:m:p:n:z:v:g:c:x:' flag; do
  case "${flag}" in
    i) IMAGE_NAME=${OPTARG} ;;
    f) METADATA_FILE=${OPTARG} ;;
    m) METADATA=${OPTARG} ;;
    p) PROJECT_NAME=${OPTARG} ;;
    n) VM_NAME=${OPTARG} ;;
    z) ZONE=${OPTARG} ;;
    v) MACHINE_TYPE=${OPTARG} ;;
    g) GPU_TYPE=${OPTARG} ;;
    c) GPU_COUNT=${OPTARG} ;;
    x) CONFIDENTIAL_COMPUTE_TYPE=${OPTARG} ;;
    *) print_usage ;;
  esac
done

create_vm
