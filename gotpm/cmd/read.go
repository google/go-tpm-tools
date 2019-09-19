package cmd

import (
	"fmt"

	pb "github.com/golang/protobuf/proto"
	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
	"github.com/spf13/cobra"
)

var hashAlgorithms = map[string]tpm2.Algorithm{
	"sha1":   tpm2.AlgSHA1,
	"sha256": tpm2.AlgSHA256,
}

var readCmd = &cobra.Command{
	Use:   "read <pcr>",
	Short: "Read from the TPM",
	Long:  `Read from the TPM`,
	Args:  cobra.NoArgs,
}

var pcrCmd = &cobra.Command{
	Use:   "pcr",
	Short: "Read PCRs from the TPM",
	Long: `Read PCRs from the TPM

Based on the --pcrs flag, this reads the contents of the TPM's Platform Control
Registers (PCRs). This is primarily used for testing/experimentation, since data
read in this manner is not signed by the TPM.

Optionally (using the --hashAlgo flag), you can change which hash's version of
the PCRs to read. `,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		rwc, err := openTpm()
		if err != nil {
			return err
		}
		defer rwc.Close()

		fmt.Fprintln(debugOutput(), "Reading pcrs")
		pcrList, err := tpm2tools.ReadPCRs(rwc, pcrs, hashAlgorithms[hashAlgo])
		if err != nil {
			return err
		}

		fmt.Fprintln(debugOutput(), "Writing pcrs")
		if err := pb.MarshalText(dataOutput(), pcrList); err != nil {
			return err
		}
		fmt.Fprintln(debugOutput(), "Wrote pcrs")

		return nil
	},
}

func init() {
	RootCmd.AddCommand(readCmd)
	readCmd.AddCommand(pcrCmd)
	addOutputFlag(pcrCmd)
	addPCRsFlag(pcrCmd)
	addHashAlgoFlag(pcrCmd)
}
