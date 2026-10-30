package cmd

import (
	"fmt"
	"io"
	"net/http"

	"github.com/google/go-tpm-tools/client"
)

type env struct {
	tpm        io.ReadWriter
	httpClient *http.Client

	quiet   bool
	verbose bool
	tpmPath string
}

type envOption func(*env)

func withTPM(rw io.ReadWriter) envOption {
	return func(e *env) { e.tpm = rw }
}

func withHTTPClient(c *http.Client) envOption {
	return func(e *env) { e.httpClient = c }
}

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

func (e *env) openTpm() (io.ReadWriteCloser, error) {
	if e.tpm != nil {
		return extTPMWrapper{e.tpm}, nil
	}
	rwc, err := openImpl(e.tpmPath)
	if err != nil {
		return nil, fmt.Errorf("connecting to TPM: %w", err)
	}
	return rwc, nil
}
