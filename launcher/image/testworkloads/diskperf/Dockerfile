# From current directory:
# gcloud builds submit --tag us-west1-docker.pkg.dev/confidential-space-images-dev/cs-integ-test-images/diskperf:latest --project confidential-space-images-dev
# Example metadata to configure fio:
# --metadata="^~^tee-image-reference=us-west1-docker.pkg.dev/confidential-space-images-dev/cs-integ-test-images/diskperf:latest~tee-restart-policy=Always~tee-cmd=[\"/jobs/default.fio\", \"--size=50G\", \"--numjobs=1\"]"~tee-container-log-redirect=true
FROM alpine

RUN apk add --no-cache fio
COPY jobs /jobs

LABEL "tee.launch_policy.log_redirect"="always"
LABEL "tee.launch_policy.allow_cmd_override"="true"

ENTRYPOINT ["fio"]
