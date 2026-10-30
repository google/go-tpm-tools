//go:build !windows
// +build !windows

package cmd

import (
	"io"
	"os"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/spf13/cobra"
)

func addTPMPathFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&tpmPath, "tpm-path", "",
		"path to TPM device (defaults to /dev/tpmrm0 then /dev/tpm0)")
}

// On Linux, we have to pass in the TPM path though a flag
func openImpl(tpmPath string) (io.ReadWriteCloser, error) {
	if tpmPath != "" {
		return tpm2.OpenTPM(tpmPath)
	}
	rwc, err := tpm2.OpenTPM("/dev/tpmrm0")
	if os.IsNotExist(err) {
		return tpm2.OpenTPM("/dev/tpm0")
	}
	return rwc, err
}
