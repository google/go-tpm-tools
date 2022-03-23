module github.com/google/go-tpm-tools/cmd

go 1.17

require (
	github.com/google/go-tpm v0.3.3
	github.com/google/go-tpm-tools v0.3.3
	github.com/spf13/cobra v1.3.0
	google.golang.org/protobuf v1.27.1
)

replace github.com/google/go-tpm-tools => ../
