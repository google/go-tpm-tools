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
var ExternalTPM io.ReadWriter

type ignoreClose struct {
	io.ReadWriter
}

type ignoreCloseWithEventLogGetter struct {
	ignoreClose
	client.EventLogGetter
}

func (ic ignoreClose) Close() error {
	return nil
}

func openTpm() (io.ReadWriteCloser, error) {
	if ExternalTPM != nil {
		ignoreCloser := ignoreClose{ExternalTPM}
		if elg, ok := ExternalTPM.(client.EventLogGetter); ok {
			return ignoreCloseWithEventLogGetter{ignoreCloser, elg}, nil
		}
		return ignoreCloser, nil
	}
	rwc, err := openImpl()
	if err != nil {
		return nil, fmt.Errorf("connecting to TPM: %w", err)
	}
	return rwc, nil
}
