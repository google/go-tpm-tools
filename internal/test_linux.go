package internal

import (
	"flag"
	"io"
	"testing"

	"github.com/google/go-tpm/tpm2"

	"github.com/google/go-tpm-tools/simulator"
)

var tpmPath = flag.String("tpm-path", "", "Path to Linux TPM character device (i.e. /dev/tpm0 or /dev/tpmrm0). Empty value (default) will run tests against the simulator.")

// GetTPM is a cross-platform testing helper function that retrives the
// appropriate TPM device from the flags passed into "go test".
func GetTPM(tb testing.TB) io.ReadWriteCloser {
	tb.Helper()
	if *tpmPath != "" {
		rwc, err := tpm2.OpenTPM(*tpmPath)
		if err != nil {
			tb.Fatalf("Opening TPM at %s failed: %v", *tpmPath, err)
		}
		return rwc
	}

	simulator, err := simulator.Get()
	if err != nil {
		tb.Fatalf("Simulator initialization failed: %v", err)
	}
	return simulator
}
