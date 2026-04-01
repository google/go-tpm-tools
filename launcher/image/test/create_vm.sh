#!/bin/bash
set -euxo pipefail

print_usage() {
    echo "usage: test_launcher.sh [-i imageName] [-p projectName] [-m metadata]"
    echo "  -i <imageName>: which image name to use for the VM"
    echo "  -p <imageProject>: which image project to use for the VM"
    echo "  -m <metadata>: metadata variables on VM creation; passed directly into gcloud"
    echo "  -f <metadataFromFile>: read a metadata value from a file; specified in format key=filePath"
    echo "  -n <instanceName>: instance name"
    echo "  -z <instanceZone>: instance zone"
    echo "  -c <confidentialComputing>: NONE, TDX, or SEV. Default is SEV"
    echo "  -v <machineType>: type of machine for VM (optional)"
    echo "  -g <gpuType>: type of GPU to use for the VM (optional)"
    echo "  -a <gpuCount>: number of GPU(s) to use for the VM (optional)"
    exit 1
}

create_vm() {
  if [ -z "$IMAGE_NAME" ]; then
    echo "Empty image name supplied."
    exit 1
  fi

  if [ -z "$CC" ]; then
    CC='SEV'
  fi

  CONFIDENTIAL_COMPUTE_FLAGS=""
  if [ "$CC" != "NONE" ]; then
    CONFIDENTIAL_COMPUTE_FLAGS="--confidential-compute-type=${CC}"
  fi

  if [ -z "$MACHINE_TYPE" ]; then
    if [[ "${CC}" == "SEV" ]]; then
      MACHINE_TYPE='n2d-standard-2'
    elif [[ "${CC}" == "TDX" ]]; then
      MACHINE_TYPE='c3-standard-4'
    elif [[ "${CC}" == "NONE" ]]; then
      MACHINE_TYPE='n1-standard-4' # Default for non-CC if not specified
    else
      echo "unsupported confidential computing type: ${CC}"
      exit 1
    fi
  fi

  # use the fake verifier for all tests
  FAKE_VERIFIER='test-fake-verifier=true'

  APPEND_METADATA=''
  if ! [ -z "$METADATA" ]; then
    if [[ "${METADATA}" == *"^~^"* ]]; then
      APPEND_METADATA="--metadata ${METADATA}~${FAKE_VERIFIER}"
    else
      APPEND_METADATA="--metadata ${METADATA},${FAKE_VERIFIER}"
    fi
  else
    APPEND_METADATA="--metadata ${FAKE_VERIFIER}"
  fi

  APPEND_METADATA_FILE=''
  if ! [ -z "$METADATA_FILE" ]; then
    APPEND_METADATA_FILE="--metadata-from-file ${METADATA_FILE}"
  fi

  echo 'Creating VM' ${VM_NAME} 'with image' $IMAGE_NAME

  # check the active account
  gcloud auth list

  ACCELERATOR_FLAGS=""
  if [ -n "$GPU_TYPE" ] && [ -n "$GPU_COUNT" ]; then
    ACCELERATOR_FLAGS="--accelerator=count=$GPU_COUNT,type=$GPU_TYPE"
    DISK_SIZE_GB=100
    PREEMPTIBLE_FLAG="--preemptible"
  else
    # Max disk for n2d-standard-2 (8GB memory) at 1% memory overhead.
    MIN_DISK_SIZE=11
    MAX_DISK_SIZE_GB=80
    ADDTL_DISK_RANGE=$(($MAX_DISK_SIZE_GB - $MIN_DISK_SIZE + 1))
    DISK_SIZE_GB=$(($MIN_DISK_SIZE + ($RANDOM % $ADDTL_DISK_RANGE)))
    PREEMPTIBLE_FLAG=""
  fi

  gcloud compute instances create $VM_NAME \
    $CONFIDENTIAL_COMPUTE_FLAGS \
    --maintenance-policy=TERMINATE \
    --machine-type=$MACHINE_TYPE \
    --boot-disk-size=$DISK_SIZE_GB \
    --scopes=cloud-platform \
    --zone=$ZONE \
    --image=$IMAGE_NAME \
    --image-project=$PROJECT_NAME \
    --shielded-secure-boot \
    $ACCELERATOR_FLAGS \
    $PREEMPTIBLE_FLAG \
    $APPEND_METADATA \
    $APPEND_METADATA_FILE
}

IMAGE_NAME=''
METADATA_FILE=''
METADATA=''
PROJECT_NAME=''
VM_NAME=''
ZONE=''
CC='SEV' # default using sev
MACHINE_TYPE=''
GPU_TYPE=''
GPU_COUNT=''

# In getopts, a ':' following a letter means that that flag takes an argument.
# For example, i: means -i takes an additional argument.
while getopts 'i:f:m:p:n:z:c:v:g:a:' flag; do
  case "${flag}" in
    i) IMAGE_NAME=${OPTARG} ;;
    f) METADATA_FILE=${OPTARG} ;;
    m) METADATA=${OPTARG} ;;
    p) PROJECT_NAME=${OPTARG} ;;
    n) VM_NAME=${OPTARG} ;;
    z) ZONE=${OPTARG} ;;
    c) CC=${OPTARG} ;;
    v) MACHINE_TYPE=${OPTARG} ;;
    g) GPU_TYPE=${OPTARG} ;;
    a) GPU_COUNT=${OPTARG} ;;
    *) print_usage ;;
  esac
done

create_vm
