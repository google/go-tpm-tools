package cmd

import (
	"errors"
	"io"

	"github.com/google/go-tpm-tools/client"
)

// extTPMWrapper is designed to wrap an external TPM to provide some overriding
// functions.
type extTPMWrapper struct {
	io.ReadWriter
}

// Close is no-op for extTPMWrapper to prevent it closing the underlying simulator.
func (et extTPMWrapper) Close() error {
	return nil
}

// EventLog is a workaround so the caller can call the underlying EventLogGetter function
// of the underlying TPM.
func (et extTPMWrapper) EventLog() ([]byte, error) {
	return client.GetEventLog(et.ReadWriter)
}

// testTPM returns a TPM opener for tests. If tpm is nil, the opener returns an
// error.
func testTPM(tpm io.ReadWriter) func(string) (io.ReadWriteCloser, error) {
	return func(string) (io.ReadWriteCloser, error) {
		if tpm == nil {
			return nil, errors.New("test did not provide a TPM")
		}
		return extTPMWrapper{tpm}, nil
	}
}

// execute runs gotpm with args. tpm can be nil if the command does not open a
// TPM.
func execute(args []string, tpm io.ReadWriter) error {
	root := newGotpmCmd(testTPM(tpm), nil)
	root.SetArgs(args)
	return root.Execute()
}
