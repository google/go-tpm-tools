# From current directory:
# gcloud builds submit --tag us-west1-docker.pkg.dev/confidential-space-images-dev/cs-integ-test-images/mounts_workload:latest
FROM alpine

COPY print_mounts.sh /

LABEL "tee.launch_policy.log_redirect"="always"
LABEL "tee.launch_policy.allow_mount_destinations"="/run/tmp:/var/tmp:/tmp"

ENTRYPOINT ["/print_mounts.sh"]

