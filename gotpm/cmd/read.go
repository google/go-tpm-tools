package cmd

import (
	"fmt"
	"io"

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

Based on the --pcrs flag, this reads the contents of the TPM's PCRs.

If --pcrs is not provided, all pcrs are read.

Optionally (using the --hashAlgo flag), you can change which hash's PCRs to
read.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		rwc, err := openTpm()
		if err != nil {
			return err
		}
		defer rwc.Close()

		fmt.Fprintln(debugOutput(), "Reading pcrs")
		hashAlgo, err := getHashAlgo()
		if err != nil {
			return err
		}

		if pcrs == nil {
			pcrs, err = getDefaultPcrs(rwc)
			if err != nil {
				return err
			}
		}

		pcrList, err := tpm2tools.ReadPCRs(rwc, pcrs, hashAlgo)
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

func getDefaultPcrs(rw io.ReadWriter) ([]int, error) {
	pcrCount, err := tpm2tools.GetPCRCount(rw)
	if err != nil {
		return nil, err
	}

	pcrs := make([]int, pcrCount)
	for i := 0; i < int(pcrCount); i++ {
		pcrs[i] = i
	}
	return pcrs, nil
}
