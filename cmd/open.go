package cmd

import (
	"fmt"
	"io"

	"github.com/google/go-tpm-tools/client"
)

// ExternalTPM can be set to run tests against an TPM initialized by an
// external package (like the simulator). Setting this value will make all
// gotpm commands run against it, and will prevent the cmd package from
// closing the TPM. Setting this value and closing the TPM must be managed
// by the external package.
// ExternalTPM can have a TPM simulator or a real TPM.
var ExternalTPM io.ReadWriter

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

func openTpm() (io.ReadWriteCloser, error) {
	if ExternalTPM != nil {
		return extTPMWrapper{ExternalTPM}, nil
	}
	rwc, err := openImpl()
	if err != nil {
		return nil, fmt.Errorf("connecting to TPM: %w", err)
	}
	return rwc, nil
}
