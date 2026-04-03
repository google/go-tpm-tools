# From current directory:
# GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o main .
# gcloud builds submit --tag us-west1-docker.pkg.dev/confidential-space-images-dev/cs-integ-test-images/workloadcleanup/workload:latest

FROM alpine

COPY main /

LABEL "tee.launch_policy.log_redirect"="always"

ENTRYPOINT ["/main"]
