# buf/validate

This directory contains the `validate.proto` file from the [bufbuild/protovalidate](https://github.com/bufbuild/protovalidate) project.

Because we use `protoc` instead of the `buf` CLI for protobuf generation, we must vendor this file locally so `protoc` can satisfy the `import "buf/validate/validate.proto";` statements in our API definitions, as officially documented in [Compile with protoc](https://protovalidate.com/schemas/compile-with-protoc/).

## How to update
To update to a newer version of protovalidate, run:

```bash
curl -sSL https://raw.githubusercontent.com/bufbuild/protovalidate/main/proto/protovalidate/buf/validate/validate.proto -o validate.proto
```
