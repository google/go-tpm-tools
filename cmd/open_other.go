//go:build !windows
// +build !windows

package cmd

import (
	"io"
	"os"

	"github.com/google/go-tpm/legacy/tpm2"
)

var tpmPath string

func init() {
	RootCmd.PersistentFlags().StringVar(&tpmPath, "tpm-path", "",
		"path to TPM device (defaults to /dev/tpmrm0 then /dev/tpm0)")
}

// On Linux, we have to pass in the TPM path though a flag
func openImpl() (io.ReadWriteCloser, error) {
	if tpmPath == "" {
		tpm, err := tpm2.OpenTPM("/dev/tpmrm0")
		if os.IsNotExist(err) {
			tpm, err = tpm2.OpenTPM("/dev/tpm0")
		}
		return tpm, err
	}
	return tpm2.OpenTPM(tpmPath)
}
