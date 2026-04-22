# From current directory:
# GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o main .
# gcloud builds submit --tag us-west1-docker.pkg.dev/confidential-space-images-dev/cs-integ-test-images/workloadcleanup:latest

FROM alpine

COPY main /

LABEL "tee.launch_policy.allow_cmd_override"="true"

ENTRYPOINT ["/main"]
