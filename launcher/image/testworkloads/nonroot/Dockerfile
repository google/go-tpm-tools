# Run this from the current directory:
# gcloud builds submit . --tag us-west1-docker.pkg.dev/confidential-space-images-dev/cs-integ-test-images/nonroot-container:latest --project confidential-space-images-dev

FROM alpine:latest

LABEL "tee.launch_policy.allow_env_override"="ALLOWED_OVERRIDE"
LABEL "tee.launch_policy.allow_cmd_override"="true"
LABEL "tee.launch_policy.log_redirect"="always"
LABEL "tee.launch_policy.nonroot_container"="nonrootonly"

ENTRYPOINT ["/bin/sh", "-c"]
CMD ["cat /proc/self/uid_map"]
