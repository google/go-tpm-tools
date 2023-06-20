package cmd

import (
	"errors"
	"fmt"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/spf13/cobra"
)

var readCmd = &cobra.Command{
	Use:   "read <pcr>",
	Short: "Read from the TPM",
	Long:  `Read from the TPM`,
	Args:  cobra.NoArgs,
}

var pcrHashAlgo = tpm2.AlgUnknown

var pcrCmd = &cobra.Command{
	Use:   "pcr",
	Short: "Read PCRs from the TPM",
	Long: `Read PCRs from the TPM

Based on --hash-algo and --pcrs flags, read the contents of the TPM's PCRs.

If --hash-algo is not provided, all banks of PCRs will be read.
If --pcrs is not provided, all PCRs are read for that hash algorithm.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		rwc, err := openTpm()
		if err != nil {
			return err
		}
		defer rwc.Close()

		if pcrHashAlgo != tpm2.AlgUnknown {
			sel := tpm2.PCRSelection{Hash: pcrHashAlgo, PCRs: pcrs}
			if len(sel.PCRs) == 0 {
				sel = client.FullPcrSel(sel.Hash)
			}

			fmt.Fprintf(debugOutput(), "Reading %v PCRs (%v)\n", sel.Hash, sel.PCRs)
			pcrs, err := client.ReadPCRs(rwc, sel)
			if err != nil {
				return err
			}
			return internal.FormatPCRs(dataOutput(), pcrs)
		}
		if len(pcrs) != 0 {
			return errors.New("--hash-algo must be used with --pcrs")
		}

		fmt.Fprintln(debugOutput(), "Reading all PCRs")
		banks, err := client.ReadAllPCRs(rwc)
		if err != nil {
			return err
		}

		for _, bank := range banks {
			if err = internal.FormatPCRs(dataOutput(), bank); err != nil {
				return err
			}
		}
		return nil
	},
}

var nvReadCmd = &cobra.Command{
	Use:   "nvdata",
	Short: "Read TPM NVData",
	Long: `Read NVData at a particular NVIndex

Based on the --index flag, this reads all of the NVData present at that NVIndex.
The read is authenticated with the owner hierarchy and an empty password.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		rwc, err := openTpm()
		if err != nil {
			return err
		}
		defer rwc.Close()

		data, err := tpm2.NVReadEx(rwc, tpmutil.Handle(nvIndex), tpm2.HandleOwner, "", 0)
		if err != nil {
			return err
		}
		if _, err := dataOutput().Write(data); err != nil {
			return fmt.Errorf("cannot output NVData: %w", err)
		}
		return nil
	},
}

func init() {
	RootCmd.AddCommand(readCmd)
	readCmd.AddCommand(pcrCmd)
	readCmd.AddCommand(nvReadCmd)
	addOutputFlag(pcrCmd)
	addPCRsFlag(pcrCmd)
	addHashAlgoFlag(pcrCmd, &pcrHashAlgo)
	addIndexFlag(nvReadCmd)
	nvReadCmd.MarkPersistentFlagRequired("index")
	addOutputFlag(nvReadCmd)
}
