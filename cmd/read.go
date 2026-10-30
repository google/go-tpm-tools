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

func newReadCmd(e *env) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "read <pcr>",
		Short: "Read from the TPM",
		Long:  `Read from the TPM`,
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newPCRCmd(e), newNVReadCmd(e))
	return cmd
}

func newPCRCmd(e *env) *cobra.Command {
	var (
		output      string
		pcrs        []int
		pcrHashAlgo = tpm2.AlgUnknown
	)
	cmd := &cobra.Command{
		Use:   "pcr",
		Short: "Read PCRs from the TPM",
		Long: `Read PCRs from the TPM

Based on --hash-algo and --pcrs flags, read the contents of the TPM's PCRs.

If --hash-algo is not provided, all banks of PCRs will be read.
If --pcrs is not provided, all PCRs are read for that hash algorithm.`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			rwc, err := e.openTpm()
			if err != nil {
				return err
			}
			defer rwc.Close()

			if pcrHashAlgo != tpm2.AlgUnknown {
				sel := tpm2.PCRSelection{Hash: pcrHashAlgo, PCRs: pcrs}
				if len(sel.PCRs) == 0 {
					sel = client.FullPcrSel(sel.Hash)
				}

				fmt.Fprintf(e.debugOutput(), "Reading %v PCRs (%v)\n", sel.Hash, sel.PCRs)
				pcrs, err := client.ReadPCRs(rwc, sel)
				if err != nil {
					return err
				}
				return internal.FormatPCRs(openForWrite(output), pcrs)
			}
			if len(pcrs) != 0 {
				return errors.New("--hash-algo must be used with --pcrs")
			}

			fmt.Fprintln(e.debugOutput(), "Reading all PCRs")
			banks, err := client.ReadAllPCRs(rwc)
			if err != nil {
				return err
			}

			for _, bank := range banks {
				if err = internal.FormatPCRs(openForWrite(output), bank); err != nil {
					return err
				}
			}
			return nil
		},
	}
	addOutputFlag(cmd, &output)
	addPCRsFlag(cmd, &pcrs)
	addHashAlgoFlag(cmd, &pcrHashAlgo)
	return cmd
}

func newNVReadCmd(e *env) *cobra.Command {
	var (
		output  string
		nvIndex uint32
	)
	cmd := &cobra.Command{
		Use:   "nvdata",
		Short: "Read TPM NVData",
		Long: `Read NVData at a particular NVIndex

Based on the --index flag, this reads all of the NVData present at that NVIndex.
The read is authenticated with the owner hierarchy and an empty password.`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			rwc, err := e.openTpm()
			if err != nil {
				return err
			}
			defer rwc.Close()

			data, err := tpm2.NVReadEx(rwc, tpmutil.Handle(nvIndex), tpm2.HandleOwner, "", 0)
			if err != nil {
				return err
			}
			if _, err := openForWrite(output).Write(data); err != nil {
				return fmt.Errorf("cannot output NVData: %w", err)
			}
			return nil
		},
	}
	addIndexFlag(cmd, &nvIndex)
	cmd.MarkPersistentFlagRequired("index")
	addOutputFlag(cmd, &output)
	return cmd
}
