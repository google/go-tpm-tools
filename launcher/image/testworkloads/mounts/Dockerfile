# From current directory:
# gcloud builds submit --tag us-west1-docker.pkg.dev/confidential-space-images-dev/cs-integ-test-images/mounts_workload:latest
FROM alpine

COPY print_mounts.sh /

LABEL "tee.launch_policy.log_redirect"="always"

ENTRYPOINT ["/print_mounts.sh"]

