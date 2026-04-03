# From current directory:
# gcloud builds submit --tag us-west1-docker.pkg.dev/confidential-space-images-dev/cs-integ-test-images/workloadcleanup/monitor:latest

FROM alpine

RUN apk add --no-cache sudo netcat-openbsd

LABEL "tee.launch_policy.log_redirect"="always"

# Listen on UDP port 2020 and pipe output to serial port ttyS0
ENTRYPOINT ["sh", "-c", "nc -ulp 2020 | sudo tee /dev/ttyS0"]
