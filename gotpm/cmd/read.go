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

Based on the --pcrs and --hash-algo flags, this reads the contents of the TPM's
PCRs for that hash algorithm.

If --pcrs is not provided, all pcrs are read.
If --hash-algo is not provided, sha256 is assumed.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		rwc, err := openTpm()
		if err != nil {
			return err
		}
		defer rwc.Close()

		hashAlgo, err := getHashAlgo()
		if err != nil {
			return err
		}

		if pcrs == nil {
			if pcrs, err = getDefaultPcrs(rwc); err != nil {
				return err
			}
		}

		fmt.Fprintln(debugOutput(), "Reading pcrs (%v)", getDefaultPcrs)
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
