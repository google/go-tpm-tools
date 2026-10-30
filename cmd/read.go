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

func newReadCmd(o *gotpmOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "read <pcr>",
		Short: "Read from the TPM",
		Long:  `Read from the TPM`,
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newPCRCmd(o), newNVReadCmd(o))
	return cmd
}

type pcrOptions struct {
	output   string
	pcrs     []int
	hashAlgo tpm2.Algorithm
}

func newPCRCmd(o *gotpmOptions) *cobra.Command {
	opts := pcrOptions{
		hashAlgo: tpm2.AlgUnknown,
	}
	cmd := &cobra.Command{
		Use:   "pcr",
		Short: "Read PCRs from the TPM",
		Long: `Read PCRs from the TPM

Based on --hash-algo and --pcrs flags, read the contents of the TPM's PCRs.

If --hash-algo is not provided, all banks of PCRs will be read.
If --pcrs is not provided, all PCRs are read for that hash algorithm.`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			rwc, err := o.openTPM()
			if err != nil {
				return err
			}
			defer rwc.Close()

			if opts.hashAlgo != tpm2.AlgUnknown {
				sel := tpm2.PCRSelection{Hash: opts.hashAlgo, PCRs: opts.pcrs}
				if len(sel.PCRs) == 0 {
					sel = client.FullPcrSel(sel.Hash)
				}

				fmt.Fprintf(o.debugOutput(), "Reading %v PCRs (%v)\n", sel.Hash, sel.PCRs)
				pcrs, err := client.ReadPCRs(rwc, sel)
				if err != nil {
					return err
				}
				return internal.FormatPCRs(openForWrite(opts.output), pcrs)
			}
			if len(opts.pcrs) != 0 {
				return errors.New("--hash-algo must be used with --pcrs")
			}

			fmt.Fprintln(o.debugOutput(), "Reading all PCRs")
			banks, err := client.ReadAllPCRs(rwc)
			if err != nil {
				return err
			}

			for _, bank := range banks {
				if err = internal.FormatPCRs(openForWrite(opts.output), bank); err != nil {
					return err
				}
			}
			return nil
		},
	}
	flags := cmd.PersistentFlags()
	flags.StringVar(&opts.output, "output", "", "output file (defaults to stdout)")
	flags.Var(&pcrsFlag{&opts.pcrs}, "pcrs", "comma separated list of PCR numbers")
	hashAlgo := algoFlag{&opts.hashAlgo, []tpm2.Algorithm{tpm2.AlgSHA1, tpm2.AlgSHA256, tpm2.AlgSHA384, tpm2.AlgSHA512}}
	flags.Var(&hashAlgo, "hash-algo", "hash algorithm: "+hashAlgo.Allowed())
	return cmd
}

type nvReadOptions struct {
	output  string
	nvIndex uint32
}

func newNVReadCmd(o *gotpmOptions) *cobra.Command {
	var opts nvReadOptions
	cmd := &cobra.Command{
		Use:   "nvdata",
		Short: "Read TPM NVData",
		Long: `Read NVData at a particular NVIndex

Based on the --index flag, this reads all of the NVData present at that NVIndex.
The read is authenticated with the owner hierarchy and an empty password.`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			rwc, err := o.openTPM()
			if err != nil {
				return err
			}
			defer rwc.Close()

			data, err := tpm2.NVReadEx(rwc, tpmutil.Handle(opts.nvIndex), tpm2.HandleOwner, "", 0)
			if err != nil {
				return err
			}
			if _, err := openForWrite(opts.output).Write(data); err != nil {
				return fmt.Errorf("cannot output NVData: %w", err)
			}
			return nil
		},
	}
	flags := cmd.PersistentFlags()
	flags.Uint32Var(&opts.nvIndex, "index", 0, "NVDATA index, cannot be 0")
	cmd.MarkPersistentFlagRequired("index")
	flags.StringVar(&opts.output, "output", "", "output file (defaults to stdout)")
	return cmd
}
