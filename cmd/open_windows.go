package cmd

import (
	"io"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/spf13/cobra"
)

func addTPMPathFlag(_ *cobra.Command) {}

// There is no need for flags on Windows, as there is no concept of a TPM path.
func openImpl(_ string) (io.ReadWriteCloser, error) {
	return tpm2.OpenTPM()
}
