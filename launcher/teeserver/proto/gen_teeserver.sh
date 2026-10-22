#!/bin/bash

protoc -I. -I../../../ -I../../../proto --go_out=. --go_opt=module=github.com/google/go-tpm-tools/launcher/teeserver/proto  --experimental_allow_proto3_optional teeserver.proto
