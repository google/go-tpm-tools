FROM golang:latest
RUN apt-get update && apt-get install -y libssl-dev
