package cmd

import (
	"fmt"
	"io"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

var keyType = "default"

var attestationKeys = map[string]map[tpm2.Algorithm]func(rw io.ReadWriter) (*client.Key, error){
	"default": {
		tpm2.AlgRSA: client.AttestationKeyRSA,
		tpm2.AlgECC: client.AttestationKeyECC,
	},
	"gce": {
		tpm2.AlgRSA: client.GceAttestationKeyRSA,
		tpm2.AlgECC: client.GceAttestationKeyECC,
	},
}

var attestCmd = &cobra.Command{
	Use:   "attest <default | gce>",
	Short: "Create a remote attestation protobuf",
	Long: `Create a remote attestation protobuf

	The Attestation protobuf contains a Quote on all available PCR banks,
	a way to validate the quote, and a TCG Event Log (Linux only).

	The optional argument specifies the type of attestation key to create.
	The command supports two attestation key types:
	- DefaultAttestationKey
	- GceAttestationKey.
	The tool will generate the key if necessary and load the key for use.
	The RSA key is used by default.
	Use --algo to override the public key algorithm for the key.

	--nonce attaches a nonce as extra data to the quote, guaranteeing a
	fresh quote.
	`,
	Args: cobra.ExactValidArgs(1),
	ValidArgs: func() []string {
		// The keys from the hierarchyNames map are our valid arguments
		aks := make([]string, len(attestationKeys))
		for ak := range attestationKeys {
			aks = append(aks, ak)
		}
		return aks
	}(),
	RunE: func(cmd *cobra.Command, args []string) error {
		rwc, err := openTpm()
		if err != nil {
			return err
		}
		defer rwc.Close()

		createFunc := attestationKeys[keyType][keyAlgo]
		fmt.Fprintf(debugOutput(), "using key and algo: %v, %v\n", keyType, keyAlgo)

		key, err := createFunc(rwc)
		if err != nil {
			return fmt.Errorf("failed to create attestation key: %v", err)
		}
		defer key.Close()

		attestation, err := key.Attest(nonce, nil)
		if err != nil {
			return err
		}

		fmt.Fprintf(debugOutput(), "Formatted proto:\n%v", prototext.Format(attestation))
		out, err := proto.Marshal(attestation)
		if err != nil {
			return fmt.Errorf("failed to marshal attestation proto: %v", attestation)
		}
		if _, err := dataOutput().Write(out); err != nil {
			return fmt.Errorf("failed to write attestation proto: %v", err)
		}
		return nil
	},
}

func init() {
	RootCmd.AddCommand(attestCmd)
	addNonceFlag(attestCmd)
	addPublicKeyAlgoFlag(attestCmd)
	addOutputFlag(attestCmd)
}
