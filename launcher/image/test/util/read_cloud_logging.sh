#!/bin/bash

# read_cloud_logging reads the cloud logging of a test VM. It reads the logs for 1 day.
# It assumes the PROJECT_ID environment variable is set.
# Use var=$(read_cloud_logging <VM_NAME>) to capture the output of this command into a variable.
read_cloud_logging() {
  gcloud logging read "resource.type=\"gce_instance\" jsonPayload._HOSTNAME=\"$1\"
log_name=\"projects/$PROJECT_ID/logs/confidential-space-launcher\"" \
--format="value(jsonPayload.MESSAGE)" --order asc
}
