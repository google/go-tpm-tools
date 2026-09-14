//go:build !linux
// +build !linux

package cmd

import (
	"errors"
	"io"
)

// openIPMI is unsupported outside of Linux, as the Google Titan IPMI transport
// relies on the Linux IPMI character device (/dev/ipmi0).
func openIPMI(string) (io.ReadWriteCloser, error) {
	return nil, errors.New("the IPMI TPM interface is only supported on Linux")
}
