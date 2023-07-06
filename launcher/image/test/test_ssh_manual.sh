#!/bin/bash
set -euxo pipefail

print_usage() {
    echo "usage: test_ssh_manual.sh [-i imageName] [-p imageProject]"
    echo "  -i <imageName>: which image name to use for the VM"
    echo "  -p <imageProject>: which image project to use for the VM"
    exit 1
}

run_ssh_test() {
    BUILD_ID=$(date +%s)
    HOME_DIR=$(echo ~)
    VM_NAME="cs-ssh-test-$BUILD_ID"
    WORKLOAD_IMAGE='us-west1-docker.pkg.dev/confidential-space-images-dev/cs-integ-test-images/basic-test:latest'
    ZONE="us-central1-a"

    ACCOUNT_NAME=$(gcloud config list account --format "value(core.account)" | tr @. _)
    PROJECT_NAME=$(gcloud config get-value project)

    # Create a new VM
    source create_vm.sh -n $VM_NAME -i $IMAGE_NAME -p $IMAGE_PROJECT -m tee-image-reference=$WORKLOAD_IMAGE,tee-container-log-redirect=true,enable-osconfig=TRUE -z $ZONE

    # Add an SSH public key to an OS Login profile
    gcloud compute os-login ssh-keys add --key-file=$HOME_DIR/.ssh/google_compute_engine.pub || true

    echo "Sleeping so settings have time to propagate."
    sleep 30

    # SSH into VM with script
    if [[ $IMAGE_NAME == *"debug"* ]]; then
        if ssh -i ~/.ssh/google_compute_engine -o StrictHostKeyChecking=no $ACCOUNT_NAME@nic0.$VM_NAME.$ZONE.c.$PROJECT_NAME.internal.gcpnode.com "echo 'SSHABLE'; exit" ; then
            echo "Success: SSH to host was successful"
            sed -i '$ d' ~/.ssh/known_hosts
        else
            echo "TEST FAILED: SSH to host was ussuccessful"
        fi
    else
        if ssh -i ~/.ssh/google_compute_engine -o StrictHostKeyChecking=no $ACCOUNT_NAME@nic0.$VM_NAME.$ZONE.c.$PROJECT_NAME.internal.gcpnode.com "echo 'SSHABLE'; exit" ; then
            echo "TEST FAILED: SSH to host was successful"
            sed -i '$ d' ~/.ssh/known_hosts
        else
            echo "Success: SSH to host was ussuccessful"
        fi
    fi
    

    # Clean up
    CLEANUP=true
    source cleanup.sh $VM_NAME $ZONE
}

IMAGE_NAME=''
IMAGE_PROJECT=''

# In getopts, a ':' following a letter means that that flag takes an argument.
# For example, i: means -i takes an additional argument.
while getopts 'i:p:' flag; do
  case "${flag}" in
    i) IMAGE_NAME=${OPTARG} ;;
    p) IMAGE_PROJECT=${OPTARG} ;;
    *) print_usage ;;
  esac
done

if [ -z "$IMAGE_NAME" ]; then
    echo "Empty image name supplied."
    exit 1
fi

if [ -z "$IMAGE_PROJECT" ]; then
    echo "Empty image project supplied."
    exit 1
fi

run_ssh_test
