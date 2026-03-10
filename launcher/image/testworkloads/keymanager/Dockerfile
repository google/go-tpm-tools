# Base image with Python support
FROM python:3.10-slim

# Set the working directory
WORKDIR /app

# Install the required Python packages
RUN pip install requests requests-unixsocket pyhpke

# Copy the client script
COPY client_test.py /app/client_test.py

LABEL "tee.launch_policy.allow_env_override"="ALLOWED_OVERRIDE"
LABEL "tee.launch_policy.allow_cmd_override"="true"
LABEL "tee.launch_policy.log_redirect"="always"

# Set the entrypoint to explicitly use unbuffered output so logs appear instantly
ENTRYPOINT ["python3", "-u", "/app/client_test.py"]
