// Package testutil wraps select test utilities to make them externally usable.
package testutil

import (
	"io"
	"testing"

	"github.com/google/go-tpm-tools/internal/test"
)

// GetTPM is a cross-platform testing helper function that retrives the
// appropriate TPM device from the flags passed into "go test".
//
// If using a test TPM, this will also retrieve a test eventlog. In this case,
// GetTPM extends the test event log's events into the test TPM.
func GetTPM(tb testing.TB) io.ReadWriteCloser {
	return test.GetTPM(tb)
}
