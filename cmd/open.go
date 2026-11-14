package cmd

import (
	"fmt"
	"io"

	"github.com/google/go-tpm-tools/client"
)

// ExternalTPM can be set to run tests against a TPM initialized by an
// external package (like the simulator). Commands that are package-level
// variables run against it, and the cmd package does not close it. Setting
// this value and closing the TPM must be managed by the external package.
// Commands built by constructors, such as flush, ignore ExternalTPM and use
// the TPM opener passed to newGotpmCmd instead.
// ExternalTPM can have a TPM simulator or a real TPM.
var ExternalTPM io.ReadWriter

// TODO: Move tpmPath into gotpmOptions after every command is built by a
// constructor. Until then, commands that are package-level variables read it
// through openTPM.
var tpmPath string

// extTPMWrapper is designed to wrap the ExternalTPM to provide some overriding
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

func openTPM() (io.ReadWriteCloser, error) {
	if ExternalTPM != nil {
		return extTPMWrapper{ExternalTPM}, nil
	}
	rwc, err := openImpl(tpmPath)
	if err != nil {
		return nil, fmt.Errorf("connecting to TPM: %w", err)
	}
	return rwc, nil
}

func (o *gotpmOptions) openTPM() (io.ReadWriteCloser, error) {
	rwc, err := o.tpmOpener(tpmPath)
	if err != nil {
		return nil, fmt.Errorf("connecting to TPM: %w", err)
	}
	return rwc, nil
}
