package cmd

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var (
	persistForce  bool
	persistDelete bool
)

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt data with a key persisted in the TPM NVRAM",
	Long: `Decrypt the input data using the TPM

TPMs can persist a private/public rsa key pair in NVRAM eg with the "sealNv"
command. The public key can be extracted with "pubkey" and used to encrypt
data with openssl. This data can only be decrypted by the TPM using the
invisible and inaccessible private key.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		var err error
		var keyHandle tpmutil.Handle

		rwc, err := openTpm()
		if err != nil {
			return err
		}
		defer rwc.Close()

		fmt.Fprintln(debugOutput(), "Loading SRK")
		srk, err := getSRK(rwc)
		if err != nil {
			return err
		}
		defer srk.Close()

		fmt.Fprintln(debugOutput(), "Reading encrypted data")
		secret, err := io.ReadAll(dataInput())
		if err != nil {
			return err
		}

		if nvIndex > 0 {
			keyHandle = tpmutil.Handle(nvIndex)
		} else {
			keyHandle = srk.Handle()
			fmt.Printf("%w\n", srk.PublicArea())
		}

		fmt.Fprintln(debugOutput(), "Decrypting data")
		decrypted, err := tpm2.RSADecrypt(rwc, keyHandle, "", secret,
			&tpm2.AsymScheme{Alg: tpm2.AlgRSAES}, "")
		if err != nil {
			return fmt.Errorf("RSADecrypt: %w", err)
		}
		fmt.Fprintln(debugOutput(), "Writing decrypted data")
		if _, err := dataOutput().Write(decrypted); err != nil {
			return fmt.Errorf("writing decrypted data: %w", err)
		}
		return nil
	},
}

var persistCmd = &cobra.Command{
	Use:   "persist",
	Short: "Generate RSA key pair and persist to TPM NVRAM",
	Long: `Generate RSA key pair and persist to TPM NVRAM

Persist a private/public rsa key pair that was freshly generated to the
TPM NVRAM. The public key can be extracted with "pubkey" and used to encrypt
data with openssl. This data can only be decrypted by the TPM using the
invisible and inaccessible private key.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		var err error

		if nvIndex == 0 {
			return fmt.Errorf("a persistent handle must be specified with --index!")
		}

		rwc, err := openTpm()
		if err != nil {
			return err
		}
		defer rwc.Close()

		fmt.Fprintln(debugOutput(), "Loading SRK")
		srk, err := getSRK(rwc)
		if err != nil {
			return err
		}
		defer srk.Close()

		if persistDelete {
			err = srk.PersistDel(nvIndex)
		} else {
			err = srk.PersistNewRSAKey(nvIndex, persistForce)
		}
		return err
	},
}

func init() {
	RootCmd.AddCommand(decryptCmd)
	RootCmd.AddCommand(persistCmd)
	addInputFlag(decryptCmd)
	addOutputFlag(decryptCmd)
	addIndexFlag(decryptCmd)
	addIndexFlag(persistCmd)
	addPublicKeyAlgoFlag(decryptCmd)
	persistCmd.PersistentFlags().BoolVarP(&persistForce, "force", "f", false, "overwrite an old object at index in NVRAM")
	persistCmd.PersistentFlags().BoolVarP(&persistDelete, "delete", "D", false, "remove an old object at index in NVRAM")
}
