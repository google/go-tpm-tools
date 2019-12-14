package cmd

import (
	"fmt"

	pb "github.com/golang/protobuf/proto"
	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/spf13/cobra"
)

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

Based on the --pcrs and --hash-algo flags, this reads the contents of the TPM's
PCRs for that hash algorithm.

If --pcrs is not provided, all pcrs are read for that hash algorithm.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		rwc, err := openTpm()
		if err != nil {
			return err
		}
		defer rwc.Close()

		sel := getSelection()
		if len(sel.PCRs) == 0 {
			sel = tpm2tools.FullPcrSel(hashAlgo)
		}

		fmt.Fprintf(debugOutput(), "Reading pcrs (%v)\n", sel.PCRs)
		pcrList, err := tpm2tools.ReadPCRs(rwc, sel)
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
