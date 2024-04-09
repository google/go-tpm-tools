//go:build !windows
// +build !windows

package cmd

import (
	"io"
	"os"

	"github.com/google/go-tpm/legacy/tpm2"
)

var tpmPath string

// tpmWrapper wrap tpm io.ReadWriteCloser and EventLogGetter interfaces together.
type tpmWrapper struct {
	io.ReadWriteCloser
}

// EventLog allows caller to call the EventLogGetter function
// of the wrapped TPM.
func (et tpmWrapper) EventLog() ([]byte, error) {
	return os.ReadFile(eventLog)
}

func init() {
	RootCmd.PersistentFlags().StringVar(&tpmPath, "tpm-path", "",
		"path to TPM device (defaults to /dev/tpmrm0 then /dev/tpm0)")
}

// On Linux, we have to pass in the TPM path though a flag
func openImpl() (tpmWrapper, error) {
	tw := tpmWrapper{}
	var err error
	if tpmPath == "" {
		tw.ReadWriteCloser, err = tpm2.OpenTPM("/dev/tpmrm0")
		if os.IsNotExist(err) {
			tw.ReadWriteCloser, err = tpm2.OpenTPM("/dev/tpm0")
		}
		return tw, err
	}
	tw.ReadWriteCloser, err = tpm2.OpenTPM(tpmPath)
	return tw, err
}
