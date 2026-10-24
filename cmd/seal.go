package cmd

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/google/go-tpm-tools/client"
	pb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/legacy/tpm2"
)

func newSealCmd(e *env) *cobra.Command {
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
		RunE: func(cmd *cobra.Command, _ []string) error {
			keyAlgo, err := getAlgo(cmd, "algo")
			if err != nil {
				return err
			}
			sealHashAlgo, err := getAlgo(cmd, "hash-algo")
			if err != nil {
				return err
			}
			pcrs, err := getPCRs(cmd)
			if err != nil {
				return err
			}

			rwc, err := e.openTpm(cmd)
			if err != nil {
				return err
			}
			defer rwc.Close()

			fmt.Fprintln(debugOutput(cmd), "Loading SRK")
			srk, err := getSRK(rwc, keyAlgo)
			if err != nil {
				return err
			}
			defer srk.Close()

			fmt.Fprintln(debugOutput(cmd), "Reading sealed data")
			secret, err := io.ReadAll(dataInput(cmd))
			if err != nil {
				return err
			}

			fmt.Fprintf(debugOutput(cmd), "Sealing to PCRs: %v\n", pcrs)
			opts := client.SealOpts{Current: tpm2.PCRSelection{
				Hash: sealHashAlgo,
				PCRs: pcrs}}
			sealed, err := srk.Seal(secret, opts)
			if err != nil {
				return fmt.Errorf("sealing data: %w", err)
			}

			fmt.Fprintln(debugOutput(cmd), "Writing sealed data")
			var output []byte
			if output, err = marshalOptions.Marshal(sealed); err != nil {
				return err
			}
			if _, err = dataOutput(cmd).Write(output); err != nil {
				return err
			}
			fmt.Fprintf(debugOutput(cmd), "Sealed data to PCRs: %v\n", pcrs)
			return nil
		},
	}
	addInputFlag(cmd)
	addOutputFlag(cmd)
	// PCRs and hash algorithm only used for sealing
	addPCRsFlag(cmd)
	addHashAlgoFlag(cmd, tpm2.AlgSHA256)
	addPublicKeyAlgoFlag(cmd)
	return cmd
}

func newUnsealCmd(e *env) *cobra.Command {
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
		RunE: func(cmd *cobra.Command, _ []string) error {
			pcrs, err := getPCRs(cmd)
			if err != nil {
				return err
			}

			rwc, err := e.openTpm(cmd)
			if err != nil {
				return err
			}
			defer rwc.Close()

			fmt.Fprintln(debugOutput(cmd), "Reading sealed data")
			data, err := io.ReadAll(dataInput(cmd))
			if err != nil {
				return err
			}
			var sealed pb.SealedBytes
			if err := unmarshalOptions.Unmarshal(data, &sealed); err != nil {
				return err
			}

			fmt.Fprintln(debugOutput(cmd), "Loading SRK")
			srk, err := getSRK(rwc, tpm2.Algorithm(sealed.GetSrk()))
			if err != nil {
				return err
			}
			defer srk.Close()

			fmt.Fprintln(debugOutput(cmd), "Unsealing data")

			opts := client.UnsealOpts{CertifyCurrent: tpm2.PCRSelection{
				Hash: client.CertifyHashAlgTpm,
				PCRs: pcrs}}
			secret, err := srk.Unseal(&sealed, opts)
			if err != nil {
				return fmt.Errorf("unsealing data: %w", err)
			}

			fmt.Fprintln(debugOutput(cmd), "Writing secret data")
			if _, err := dataOutput(cmd).Write(secret); err != nil {
				return fmt.Errorf("writing secret data: %w", err)
			}
			fmt.Fprintln(debugOutput(cmd), "Unsealed data using TPM")
			return nil
		},
	}
	addInputFlag(cmd)
	addOutputFlag(cmd)
	addPCRsFlag(cmd)
	return cmd
}
