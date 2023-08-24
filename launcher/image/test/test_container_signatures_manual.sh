#!/bin/bash
set -euxo pipefail
print_usage() {
    echo "usage: test_container_signatures.sh [-i imageName] [-p imageProject] [-s attestationService] [-r targetRepo]"
    echo "  -i <imageName>: which image name to use for the VM"
    echo "  -p <imageProject>: which image project to use for the VM"
    echo "  -s <attestationService>: which attestation service endpoint to test"
    echo "  -r <targetRepo>: which docker repo to store container signatures"
    exit 1
}
install_cosign() {
    echo "installing cosign library with Go"
    go install github.com/sigstore/cosign/cmd/cosign@latest
    # Add $GOPATH/bin to $PATH
    export GOPATH="$HOME/go"
    PATH="$GOPATH/bin:$PATH"
}
cosign_sign() {
    pass="$RANDOM"
    export COSIGN_PASSWORD=$pass
    export COSIGN_REPOSITORY=$TARGET_REPO

    # Generate a key pair for signing
    cosign generate-key-pair
    # Export public key and perform base64 encoding
    cosign public-key --key $SIGNING_KEY >$VERIFICATION_KEY
    PUB=$(cat ${VERIFICATION_KEY} | openssl base64)
    PUB=$(echo $PUB | tr -d '[:space:]' | sed 's/[=]*$//')
    # Use cosign sign
    cosign sign --key ${SIGNING_KEY} $WORKLOAD_IMAGE -a dev.cosignproject.cosign/sigalg=$SIG_ALG -a dev.cosignproject.cosign/pub=$PUB
}
run_container_signatures_test() {
    BUILD_ID=$(date +%s)
    HOME_DIR=$(echo ~)
    VM_NAME="cs-container-signature-test-$BUILD_ID"
    ZONE="us-central1-a"
    METADATA="tee-image-reference=$WORKLOAD_IMAGE,enable-guest-attributes=true,tee-attestation-service-endpoint=$ATTESTATION_SERVICE_ENDPOINT,tee-signed-image-repos=$TARGET_REPO,tee-restart-policy=Never,tee-container-log-redirect=true"
    gcloud config set project $PROJECT_NAME
    # Create a new VM
    gcloud compute instances create $VM_NAME --confidential-compute --maintenance-policy=TERMINATE \
        --scopes=cloud-platform --zone $ZONE --image=$IMAGE_NAME --image-project=$IMAGE_PROJECT \
        --shielded-secure-boot --metadata $METADATA --service-account=$SERVICE_ACCOUNT
    # Compute fingerprint of a public key in hex format using sha256
    fingerprint=$(openssl pkey -pubin -in ${VERIFICATION_KEY} -outform DER | sha256sum | tr -d '[:space:]' | sed 's/[-]*$//')
    # Read from serial console logs
    # This test requires the workload to run and printing
    # corresponding messages to the serial console.
    source util/read_serial.sh
    SERIAL_OUTPUT=$(read_serial $VM_NAME $ZONE)
    print_serial=false

    if echo $SERIAL_OUTPUT | grep -q ${fingerprint}; then
        echo "- token container image signature fingerprint verified"
    else
        echo "FAILED: token container image signature not verified"
        echo 'TEST FAILED.' >/workspace/status.txt
        print_serial=true
    fi
    if $print_serial; then
        echo $SERIAL_OUTPUT
    fi
    # Check test failure
    source check_failure.sh
}
clean_up() {
    # Clean up
    CLEANUP=true
    source cleanup.sh $VM_NAME $ZONE
    gcloud artifacts docker images delete -q $(cosign triangulate $WORKLOAD_IMAGE)
    (rm $SIGNING_KEY $VERIFICATION_KEY) || true
}
IMAGE_NAME=''
IMAGE_PROJECT=''
TARGET_REPO=''
ATTESTATION_SERVICE_ENDPOINT=''
SIGNING_KEY=cosign.key
VERIFICATION_KEY=cosign.pub
SIG_ALG='ECDSA_P256_SHA256'
PROJECT_NAME='confidentialcomputing-e2e'
SERVICE_ACCOUNT='testuser@confidentialcomputing-e2e.iam.gserviceaccount.com'
WORKLOAD_IMAGE='us-docker.pkg.dev/confidential-space-images-dev/cs-cosign-tests/e2e_test:latest'
# In getopts, a ':' following a letter means that that flag takes an argument.
# For example, i: means -i takes an additional argument.
while getopts 'i:p:s:r:' flag; do
    case "${flag}" in
    i) IMAGE_NAME=${OPTARG} ;;
    p) IMAGE_PROJECT=${OPTARG} ;;
    s) ATTESTATION_SERVICE_ENDPOINT=${OPTARG} ;;
    r) TARGET_REPO=${OPTARG} ;;
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
if [ -z "$ATTESTATION_SERVICE_ENDPOINT" ]; then
    echo "Empty service endpoint supplied."
    exit 1
fi
if [ -z "$TARGET_REPO" ]; then
    echo "Empty target docker repo supplied."
    exit 1
fi
install_cosign
cosign_sign
run_container_signatures_test
clean_up
