//go:build !windows
// +build !windows

package cmd

import (
	"io"
	"os"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/spf13/cobra"
)

// addTPMPathFlag lets cmd and its subcommands specify the TPM device path.
func addTPMPathFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().String("tpm-path", "",
		"path to TPM device (defaults to /dev/tpmrm0 then /dev/tpm0)")
}

// On Linux, we have to pass in the TPM path though a flag
func openImpl(cmd *cobra.Command) (io.ReadWriteCloser, error) {
	tpmPath, err := cmd.Flags().GetString("tpm-path")
	if err != nil {
		return nil, err
	}
	if tpmPath == "" {
		rwc, err := tpm2.OpenTPM("/dev/tpmrm0")
		if os.IsNotExist(err) {
			return tpm2.OpenTPM("/dev/tpm0")
		}
		return rwc, err
	}
	return tpm2.OpenTPM(tpmPath)
}
