#!/bin/bash
set -e

if [ -f /usr/share/oem/wsd/image.env ]; then
    source /usr/share/oem/wsd/image.env
else
    echo "Error: Config file not found!"
    exit 1
fi

# Task Cleanup
if ctr task ls | grep -q "$CONTAINER_NAME"; then
    echo "Stopping running task for $CONTAINER_NAME..."
    ctr task kill -s SIGTERM "$CONTAINER_NAME" || true
    
    # Poll for up to 10 seconds waiting for the task to exit naturally
    TIMEOUT=10
    while [ $TIMEOUT -gt 0 ] && ctr task ls | grep -q "$CONTAINER_NAME"; do
        sleep 1
        ((TIMEOUT--))
    done
    
    # Force delete the task if it exists
    echo "Deleting the task..."
    ctr task rm -f "$CONTAINER_NAME" || true
else
    echo "No active task found for $CONTAINER_NAME."
fi


# Container Cleanup
if ctr container ls | grep -q "$CONTAINER_NAME"; then
    echo "Found container object for $CONTAINER_NAME. Deleting..."
    
    # Attempt to delete the container
    if ! ctr container rm "$CONTAINER_NAME"; then
        echo "Attempting forced/delayed deletion of container $CONTAINER_NAME..."
        sleep 2
        ctr container rm "$CONTAINER_NAME" || { echo "Error: Failed to delete container $CONTAINER_NAME"; exit 1; }
    fi
fi

echo "Cleanup Complete!"