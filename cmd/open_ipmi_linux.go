//go:build linux
// +build linux

package cmd

import (
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/googleipmi"
)

// ipmiTPM adapts a transport.TPMCloser (command/response oriented) to the
// io.ReadWriteCloser (stream oriented) interface expected by the legacy
// go-tpm/go-tpm-tools APIs used throughout gotpm.
//
// It mimics the semantics of /dev/tpm{rm}0: a Write sends a full TPM command
// and the subsequent Read(s) return the buffered response.
type ipmiTPM struct {
	tpm      transport.TPMCloser
	response []byte
}

// Write sends the TPM command in p to the TPM and buffers the response.
func (t *ipmiTPM) Write(p []byte) (int, error) {
	rsp, err := t.tpm.Send(p)
	if err != nil {
		return 0, err
	}
	t.response = rsp
	return len(p), nil
}

// Read copies the buffered response of the last command into p. Unlike
// transport.ToReadWriter, io.EOF is only returned once the whole response has
// been consumed, so that callers reading the response in a single call (such
// as tpmutil.RunCommandRaw) do not observe an error.
func (t *ipmiTPM) Read(p []byte) (int, error) {
	if len(t.response) == 0 {
		return 0, io.EOF
	}
	n := copy(p, t.response)
	t.response = t.response[n:]
	return n, nil
}

// Close closes the underlying IPMI connection.
func (t *ipmiTPM) Close() error {
	return t.tpm.Close()
}

// ipmiDevicePath is the only IPMI device the googleipmi transport supports.
const ipmiDevicePath = "/dev/ipmi0"

// openIPMI connects to a Google Titan TPM over the IPMI interface at path.
func openIPMI(path string) (io.ReadWriteCloser, error) {
	if path != ipmiDevicePath {
		return nil, fmt.Errorf("unsupported IPMI device %q, only %q is supported", path, ipmiDevicePath)
	}
	tpm, err := googleipmi.Open()
	if err != nil {
		return nil, fmt.Errorf("opening Google IPMI TPM transport: %w", err)
	}
	return &ipmiTPM{tpm: tpm}, nil
}
