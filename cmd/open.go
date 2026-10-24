package cmd

import (
	"fmt"
	"io"
	"net/http"

	"github.com/google/go-tpm-tools/client"
	"github.com/spf13/cobra"
)

// env holds the dependencies shared by a command tree.
type env struct {
	// tpm, if set, makes all commands run against it instead of a TPM
	// device. The commands do not close it. It can be a TPM simulator or a
	// real TPM.
	tpm io.ReadWriter
	// httpClient, if set, is used by commands that call remote services.
	httpClient *http.Client
}

// envOption configures the env of a command tree.
type envOption func(*env)

// withTPM makes all commands run against rw. The caller must close rw.
func withTPM(rw io.ReadWriter) envOption {
	return func(e *env) { e.tpm = rw }
}

// withHTTPClient makes commands use c for remote services.
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

func (e *env) openTpm(cmd *cobra.Command) (io.ReadWriteCloser, error) {
	if e.tpm != nil {
		return extTPMWrapper{e.tpm}, nil
	}
	rwc, err := openImpl(cmd)
	if err != nil {
		return nil, fmt.Errorf("connecting to TPM: %w", err)
	}
	return rwc, nil
}
