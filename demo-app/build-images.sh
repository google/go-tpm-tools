#!/bin/bash
set -e

REGISTRY="gcr.io/somashekarkb-cs-codelab"

# Change to the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

echo "Building and Pushing Main Container Image to $REGISTRY..."
cd main-container
docker build -t $REGISTRY/main-app:latest .
docker push $REGISTRY/main-app:latest
cd ..

echo "Building and Pushing Sidecar Container Image to $REGISTRY..."
cd sidecar-container
docker build -t $REGISTRY/sidecar-app:latest .
docker push $REGISTRY/sidecar-app:latest
cd ..

echo "Done! Images pushed to $REGISTRY"
