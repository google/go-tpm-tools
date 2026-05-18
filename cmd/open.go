package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/googleipmi"
)

// ExternalTPM can be set to run tests against an TPM initialized by an
// external package (like the simulator). Setting this value will make all
// gotpm commands run against it, and will prevent the cmd package from
// closing the TPM. Setting this value and closing the TPM must be managed
// by the external package.
// ExternalTPM can have a TPM simulator or a real TPM.
var ExternalTPM io.ReadWriter

var useIPMI bool

func init() {
	RootCmd.PersistentFlags().BoolVar(&useIPMI, "use-ipmi", false,
		"use Google IPMI transport to talk to a Titan TPM")
}

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

// tpmWrapper wraps a TPM io.ReadWriteCloser that implements client.EventLogGetter.
type tpmWrapper struct {
	io.ReadWriteCloser
}

// EventLog fetches the event log specified by the event-log flag.
func (et tpmWrapper) EventLog() ([]byte, error) {
	return os.ReadFile(eventLog)
}

func openTpm() (io.ReadWriteCloser, error) {
	if ExternalTPM != nil {
		return extTPMWrapper{ExternalTPM}, nil
	}
	var rwc io.ReadWriteCloser
	var err error
	if useIPMI {
		tpmCloser, err := googleipmi.Open()
		if err != nil {
			return nil, fmt.Errorf("connecting to TPM via Google IPMI: %w", err)
		}
		rwc = struct {
			io.ReadWriter
			io.Closer
		}{
			transport.ToReadWriter(tpmCloser),
			tpmCloser,
		}
	} else {
		rwc, err = openImpl()
		if err != nil {
			return nil, err
		}
	}
	return tpmWrapper{rwc}, nil
}
