package cmd

import (
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/spf13/cobra"
)

// number of bytes to generate
var size uint16

var randomCmd = &cobra.Command{
	Use:   "random",
	Short: "Get random bytes from the TPM",
	Long: `Get radom bytes generated from the TPM 2.0 device, the maximum number of bytes
to return is depending on TPM2B_DIGEST size. If the given size is more than
will fit into a TPM2B_DIGEST, no error will return but the command will only
return as much data as will fit into the digest`,
	Args: cobra.ExactValidArgs(0),
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true

		rwc, err := openTpm()
		if err != nil {
			return err
		}
		defer rwc.Close()

		buf, err := tpm2.GetRandom(rwc, size)
		if err != nil {
			return err
		}
		return writeRandomBytes(buf)
	},
}

func init() {
	// Lets this command specify a size.
	randomCmd.PersistentFlags().Uint16Var(&size, "size", 0, "number of bytes to return, cannot be 0")
	randomCmd.MarkPersistentFlagRequired("size")
	RootCmd.AddCommand(randomCmd)
	addOutputFlag(randomCmd)
}

func writeRandomBytes(bytes []byte) error {
	bytesWritten, err := dataOutput().Write(bytes)
	fmt.Fprintf(debugOutput(), "rand bytes written: %d\n", bytesWritten)

	return err
}
