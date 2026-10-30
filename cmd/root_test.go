package cmd

import (
	"bytes"
	"errors"
	"io"
)

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
	root := newGotpmCmd(testTPM(tpm))
	root.SetArgs(args)
	return root.Execute()
}

// executeOutput runs gotpm with args and returns what the command wrote to its
// standard output.
func executeOutput(args []string, tpm io.ReadWriter) ([]byte, error) {
	var out bytes.Buffer
	root := newGotpmCmd(testTPM(tpm))
	root.SetArgs(args)
	root.SetOut(&out)
	err := root.Execute()
	return out.Bytes(), err
}
