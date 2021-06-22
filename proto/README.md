## Generating `tpm.pb.go`

After updating `tpm.proto` you will have to regenerate the go bindings. To do this:
  - Install [`protoc`](https://github.com/protocolbuffers/protobuf)
  - Install `protoc-gen-go`
    ```bash
    go install google.golang.org/protobuf/cmd/protoc-gen-go
    ```
  - Run the following command in the root directory of this project:
    ```bash
    protoc --go_out=. --go_opt=paths=source_relative proto/*.proto
    ```

See [the docs](https://developers.google.com/protocol-buffers/docs/reference/go-generated) for more information.
