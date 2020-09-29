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


### Workaround for https://github.com/golang/protobuf/issues/1077

In order to not have this package depend on an old version of the protobuf
library:

Delete this import from the generated file:
```go
proto "github.com/golang/protobuf/proto"
```

Delete this code from the generated file:
```go
// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4
```