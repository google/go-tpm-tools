// Package internal provides low-level bindings to the Microsoft TPM2 simulator.
//
// When using CGO, this package compiles the simulator's C code and links
// against the system OpenSSL library. Without CGO, this package just provides
// stubs which always return failure. This allows the simulator package to be
// built when cross compiling go-tpm-tools (which is incompatible with CGO).
package internal
