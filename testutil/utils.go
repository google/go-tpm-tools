// Package testutil wraps select test utilities to make them externally usable.
package testutil

import (
	"io"
	"testing"

	"github.com/google/go-tpm-tools/internal/test"
)

func GetTPM(tb testing.TB) io.ReadWriteCloser {
	return test.GetTPM(tb)
}
