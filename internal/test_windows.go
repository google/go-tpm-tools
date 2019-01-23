package internal

import (
	"flag"
	"io"
	"testing"

	"github.com/google/go-tpm/tpm2"

	"github.com/google/go-tpm-tools/simulator"
)

var useTBS = flag.Bool("use-tbs", false, "Run the tests against the Windows TBS. Value of false (default) will run tests against the simulator.")

// GetTPM is a cross-platform testing helper function that retrives the
// appropriate TPM device from the flags passed into "go test".
func GetTPM(tb testing.TB) io.ReadWriteCloser {
	tb.Helper()
	if useTBS {
		rwc, err := tpm2.OpenTPM()
		if err != nil {
			tb.Fatalf("Initializing Windows TBS failed: %v", err)
		}
		return rwc
	}

	simulator, err := simulator.Get()
	if err != nil {
		tb.Fatalf("Initializing simulator failed: %v", err)
	}
	return simulator
}
