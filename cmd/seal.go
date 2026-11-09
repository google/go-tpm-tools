package cmd

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/google/go-tpm-tools/client"
	pb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/legacy/tpm2"
)

type sealOptions struct {
	input        string
	output       string
	pcrs         []int
	keyAlgo      tpm2.Algorithm
	sealHashAlgo tpm2.Algorithm
}

func newSealCmd(o *gotpmOptions) *cobra.Command {
	opts := sealOptions{
		keyAlgo:      tpm2.AlgRSA,
		sealHashAlgo: tpm2.AlgSHA256,
	}
	cmd := &cobra.Command{
		Use:   "seal",
		Short: "Seal some data to the TPM",
		Long: `Encrypt the input data using the TPM

TPMs support a "sealing" operation that allows some secret data to be encrypted
by a particular TPM. This data can only be decrypted by the same TPM that did
the encryption.

Optionally (using the --pcrs flag), this decryption can be furthur restricted to
only work if certain Platform Control Registers (PCRs) are in the correct state.
This allows a key (i.e. a disk encryption key) to be bound to specific machine
state (like Secure Boot).`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			rwc, err := o.openTPM()
			if err != nil {
				return err
			}
			defer rwc.Close()

			fmt.Fprintln(o.debugOutput(), "Loading SRK")
			srk, err := getSRK(rwc, opts.keyAlgo)
			if err != nil {
				return err
			}
			defer srk.Close()

			fmt.Fprintln(o.debugOutput(), "Reading sealed data")
			secret, err := io.ReadAll(dataInput(opts.input))
			if err != nil {
				return err
			}

			fmt.Fprintf(o.debugOutput(), "Sealing to PCRs: %v\n", opts.pcrs)
			sealOpts := client.SealOpts{Current: tpm2.PCRSelection{
				Hash: opts.sealHashAlgo,
				PCRs: opts.pcrs}}
			sealed, err := srk.Seal(secret, sealOpts)
			if err != nil {
				return fmt.Errorf("sealing data: %w", err)
			}

			fmt.Fprintln(o.debugOutput(), "Writing sealed data")
			var out []byte
			if out, err = marshalOptions.Marshal(sealed); err != nil {
				return err
			}
			if _, err = openForWrite(opts.output).Write(out); err != nil {
				return err
			}
			fmt.Fprintf(o.debugOutput(), "Sealed data to PCRs: %v\n", opts.pcrs)
			return nil
		},
	}
	flags := cmd.PersistentFlags()
	flags.StringVar(&opts.input, "input", "", "input file (defaults to stdin)")
	flags.StringVar(&opts.output, "output", "", "output file (defaults to stdout)")
	// PCRs and hash algorithm only used for sealing
	flags.Var(&pcrsFlag{&opts.pcrs}, "pcrs", "comma separated list of PCR numbers")
	hashAlgo := algoFlag{&opts.sealHashAlgo, []tpm2.Algorithm{tpm2.AlgSHA1, tpm2.AlgSHA256, tpm2.AlgSHA384, tpm2.AlgSHA512}}
	flags.Var(&hashAlgo, "hash-algo", "hash algorithm: "+hashAlgo.Allowed())
	algo := algoFlag{&opts.keyAlgo, []tpm2.Algorithm{tpm2.AlgRSA, tpm2.AlgECC}}
	flags.Var(&algo, "algo", "public key algorithm: "+algo.Allowed())
	return cmd
}

type unsealOptions struct {
	input  string
	output string
	pcrs   []int
}

func newUnsealCmd(o *gotpmOptions) *cobra.Command {
	var opts unsealOptions
	cmd := &cobra.Command{
		Use:   "unseal",
		Short: "Unseal some data previously sealed to the TPM",
		Long: `Decrypt the input data using the TPM

The opposite of "gotpm seal". This takes in some sealed input and decrypts it
using the TPM. This operation will fail if used on a different TPM, or if the
Platform Control Registers (PCRs) are in the incorrect state.

All the necessary data to decrypt the sealed input is present in the input blob.
We do not need to specify the PCRs used for unsealing.

We do support an optional "certification" process. A list of PCRs may be
provided with --pcrs, and the unwrapping will fail if the PCR values when
sealing differ from the current PCR values. This allows for verification of the
machine state when sealing took place.
`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			rwc, err := o.openTPM()
			if err != nil {
				return err
			}
			defer rwc.Close()

			fmt.Fprintln(o.debugOutput(), "Reading sealed data")
			data, err := io.ReadAll(dataInput(opts.input))
			if err != nil {
				return err
			}
			var sealed pb.SealedBytes
			if err := unmarshalOptions.Unmarshal(data, &sealed); err != nil {
				return err
			}

			fmt.Fprintln(o.debugOutput(), "Loading SRK")
			srk, err := getSRK(rwc, tpm2.Algorithm(sealed.GetSrk()))
			if err != nil {
				return err
			}
			defer srk.Close()

			fmt.Fprintln(o.debugOutput(), "Unsealing data")

			unsealOpts := client.UnsealOpts{CertifyCurrent: tpm2.PCRSelection{
				Hash: client.CertifyHashAlgTpm,
				PCRs: opts.pcrs}}
			secret, err := srk.Unseal(&sealed, unsealOpts)
			if err != nil {
				return fmt.Errorf("unsealing data: %w", err)
			}

			fmt.Fprintln(o.debugOutput(), "Writing secret data")
			if _, err := openForWrite(opts.output).Write(secret); err != nil {
				return fmt.Errorf("writing secret data: %w", err)
			}
			fmt.Fprintln(o.debugOutput(), "Unsealed data using TPM")
			return nil
		},
	}
	flags := cmd.PersistentFlags()
	flags.StringVar(&opts.input, "input", "", "input file (defaults to stdin)")
	flags.StringVar(&opts.output, "output", "", "output file (defaults to stdout)")
	flags.Var(&pcrsFlag{&opts.pcrs}, "pcrs", "comma separated list of PCR numbers")
	return cmd
}
