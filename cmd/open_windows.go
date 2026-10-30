package cmd

import (
	"io"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/spf13/cobra"
)

// There is no need for flags on Windows, as there is no concept of a TPM path.
func addTPMPathFlag(_ *cobra.Command, _ *string) {}

func openImpl(_ string) (io.ReadWriteCloser, error) {
	return tpm2.OpenTPM()
}
