# From current directory:
# gcloud builds submit --tag us-west1-docker.pkg.dev/confidential-space-images-dev/cs-integ-test-images/keyclaims-workload:latest --project confidential-space-images-dev
FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir requests requests-unixsocket

COPY workload.py .

RUN mkdir -p /run/container_launcher

CMD ["python", "workload.py"]
