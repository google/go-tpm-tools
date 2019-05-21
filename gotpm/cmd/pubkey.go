package cmd

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpmutil"

	"github.com/google/go-tpm/tpm2"
	"github.com/spf13/cobra"
)

var hierarchyNames = map[string]tpmutil.Handle{
	"endorsement": tpm2.HandleEndorsement,
	"owner":       tpm2.HandleOwner,
	"platform":    tpm2.HandlePlatform,
	"null":        tpm2.HandleNull,
}

var pubkeyCmd = &cobra.Command{
	Use:   "pubkey <endorsement | owner | platform | null>",
	Short: "Retrieve a public key from the TPM",
	Long: `Get the PEM-formatted public component of a TPM's primary key

A TPM can create a primary asymetric key in one of 4 hierarchies:
	endorsement - used for remote attestation, privacy sensitive
	owner       - used for local signing/encryption, reset on TPM2_Clear
	platform    - rarely used
	null        - all keys are ephemeral, reset on every boot

Furthermore, this key is based on a template containing parameters like
algorithms and key sizes. By default, this command uses a standard template
defined in the TPM2 spec. If --index is provided, the template is read from
NVDATA instead (and --algo is ignored).`,
	ValidArgs: func() []string {
		// The keys from the hierarchyNames map are our valid arguments
		keys := make([]string, len(hierarchyNames))
		for k := range hierarchyNames {
			keys = append(keys, k)
		}
		return keys
	}(),
	Args: cobra.ExactValidArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		algo, err := getAlgo()
		if err != nil {
			return err
		}
		cmd.SilenceUsage = true

		rwc, err := openTpm()
		if err != nil {
			return err
		}
		defer rwc.Close()

		key, err := getKey(rwc, hierarchyNames[args[0]], algo)
		if err != nil {
			return err
		}
		defer key.Close()

		return writeKey(key.PublicKey())
	},
}

var keyAlgo string

func init() {
	RootCmd.AddCommand(pubkeyCmd)
	addIndexFlag(pubkeyCmd)
	addOutputFlag(pubkeyCmd)
	pubkeyCmd.PersistentFlags().StringVar(&keyAlgo, "algo", "rsa",
		"Public key algorithm, \"rsa\" or \"ecc\"")
}

func getAlgo() (tpm2.Algorithm, error) {
	switch keyAlgo {
	case "rsa":
		return tpm2.AlgRSA, nil
	case "ecc":
		return tpm2.AlgECC, nil
	case "":
		panic("--algo flag not properly setup")
	default:
		return tpm2.AlgNull, fmt.Errorf("invalid argument %q for \"--algo\" flag", keyAlgo)
	}
}

func getKey(rw io.ReadWriter, hierarchy tpmutil.Handle, algo tpm2.Algorithm) (*tpm2tools.Key, error) {
	fmt.Fprintf(debugOutput(), "Using hierarchy 0x%x\n", hierarchy)
	if nvIndex != 0 {
		fmt.Fprintf(debugOutput(), "Reading from NVDATA index %d\n", nvIndex)
		return tpm2tools.KeyFromNvIndex(rw, hierarchy, nvIndex)
	}

	switch algo {
	case tpm2.AlgRSA:
		switch hierarchy {
		case tpm2.HandleEndorsement:
			return tpm2tools.EndorsementKeyRSA(rw)
		case tpm2.HandleOwner:
			return tpm2tools.StorageRootKeyRSA(rw)
		default:
			return nil, fmt.Errorf("There is no default RSA key for this hierarchy")
		}
	case tpm2.AlgECC:
		return nil, fmt.Errorf("ECDSA keys are not yet supported")
	default:
		panic("Unreachable")
	}
}

func writeKey(pubKey crypto.PublicKey) error {
	fmt.Fprintf(debugOutput(), "Got key: %+v\n", pubKey)
	asn1Bytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return err
	}

	return pem.Encode(dataOutput(), &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	})
}
