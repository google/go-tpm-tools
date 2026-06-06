// Package envinit provides automated bootstrapping of process environment flags.
//
// Must be imported as the absolute first import in any files that pull in conflicting proto packages:
//
//	import _ "github.com/google/go-tpm-tools/launcher/teeserver/envinit"
//
// ### The Problem
// Both the following packages:
// - "github.com/google/go-tpm-tools/keymanager/km_common/proto"
// - "github.com/GoogleCloudPlatform/key-protection-module/km_common/proto"
//
// compile and register the same relative proto file paths (such as "km_common/proto/algorithms.proto").
// By default, the Go protobuf runtime (google.golang.org/protobuf) panics if a proto path is
// registered more than once in the process namespace.
//
// ### The Solution
// Setting GOLANG_PROTOBUF_REGISTRATION_CONFLICT=warn downgrades the namespace duplicate check
// panic to a non-fatal warning message.
//
// ### Why this is a Bootstrapping Package
// Go package initialization runs transitively. If an imported package's init() panics, we cannot
// intercept it in our own package's init() because imported packages are initialized first.
// By placing this environment setup in a standalone bootstrapping package and listing its import
// lexically first, we ensure that os.Setenv is called BEFORE Go's runtime imports and initializers
// register the conflicting proto files.
package envinit

import "os"

func init() {
	os.Setenv("GOLANG_PROTOBUF_REGISTRATION_CONFLICT", "warn")
}
