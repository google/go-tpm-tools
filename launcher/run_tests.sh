#!/bin/bash
set -euo pipefail

IMAGE_NAME=""
PROJECT_NAME=""
TEST_FILE=""

usage() {
  echo "Usage: $0 -i <image_name> -p <project_name> -t <test_name>"
  echo "Available tests:"
  echo "  test_ingress_network.yaml"
  echo "  test_experiments_client.yaml"
  echo "  test_health_monitoring.yaml"
  echo "  test_discover_signatures.yaml"
  echo "  test_http_server.yaml"
  echo "  test_keymanager_cloudbuild.yaml"
  echo "  test_launchpolicy_cloudbuild.yaml"
  echo "  test_log_redirection.yaml"
  echo "  test_memory_monitoring.yaml"
  echo "  test_mounts.yaml"
  echo "  test_oda_with_signed_container.yaml"
  echo "  test_privileged.yaml"
  exit 1
}

while getopts 'i:p:t:' flag; do
  case "${flag}" in
    i) IMAGE_NAME=${OPTARG} ;;
    p) PROJECT_NAME=${OPTARG} ;;
    t) TEST_FILE=${OPTARG} ;;
    *) usage ;;
  esac
done

if [ -z "$IMAGE_NAME" ] || [ -z "$PROJECT_NAME" ] || [ -z "$TEST_FILE" ]; then
  usage
fi

echo "Running test ${TEST_FILE} on image ${IMAGE_NAME} in project ${PROJECT_NAME}..."

cd image/test
gcloud builds submit --config="${TEST_FILE}" \
  --substitutions _IMAGE_NAME="${IMAGE_NAME}",_IMAGE_PROJECT="${PROJECT_NAME}" \
  --region us-west1

