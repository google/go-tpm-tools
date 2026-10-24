package cmd

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	directtpm2 "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/spf13/cobra"
)

func addKeyFormatFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().String("key-format", "pem", "type of format for the outputted key, defaults to pem, but can also specify tpmt-public")
}

var hierarchyNames = map[string]tpmutil.Handle{
	"endorsement": tpm2.HandleEndorsement,
	"owner":       tpm2.HandleOwner,
	"platform":    tpm2.HandlePlatform,
	"null":        tpm2.HandleNull,
}

func newPubkeyCmd(e *env) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pubkey <endorsement | owner | platform | null>",
		Short: "Retrieve a public key from the TPM",
		Long: `Get the PEM-formatted public component of a TPM's primary key

A TPM can create a primary asymmetric key in one of 4 hierarchies:
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
		Args: cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			keyAlgo, err := getAlgo(cmd, "algo")
			if err != nil {
				return err
			}
			nvIndex, err := cmd.Flags().GetUint32("index")
			if err != nil {
				return err
			}
			keyFormat, err := cmd.Flags().GetString("key-format")
			if err != nil {
				return err
			}

			rwc, err := e.openTpm(cmd)
			if err != nil {
				return err
			}
			defer rwc.Close()

			key, err := getKey(debugOutput(cmd), rwc, hierarchyNames[args[0]], keyAlgo, nvIndex)
			if err != nil {
				return err
			}
			defer key.Close()

			if keyFormat == "pem" {
				return writeKey(debugOutput(cmd), dataOutput(cmd), key.PublicKey())
			}
			if keyFormat == "tpmt-public" {
				encoded, err := key.PublicArea().Encode()
				if err != nil {
					return fmt.Errorf("failed to encode public area: %v", err)
				}
				_, err = dataOutput(cmd).Write(encoded)
				if err != nil {
					return fmt.Errorf("failed to write key: %v", err)
				}
				return nil
			}
			return fmt.Errorf("key format must be either pem or tpmt-public")

		},
	}
	addIndexFlag(cmd)
	addOutputFlag(cmd)
	addPublicKeyAlgoFlag(cmd)
	addKeyFormatFlag(cmd)
	return cmd
}

func getKey(debug io.Writer, rw io.ReadWriter, hierarchy tpmutil.Handle, keyAlgo tpm2.Algorithm, nvIndex uint32) (*client.Key, error) {
	fmt.Fprintf(debug, "Using hierarchy 0x%x\n", hierarchy)
	if nvIndex != 0 {
		fmt.Fprintf(debug, "Reading from NVDATA index %d\n", nvIndex)
		return client.KeyFromNvIndex(rw, hierarchy, nvIndex)
	}

	switch hierarchy {
	case tpm2.HandleEndorsement:
		return getEK(rw, keyAlgo)
	case tpm2.HandleOwner:
		return getSRK(rw, keyAlgo)
	default:
		return nil, fmt.Errorf("there is no default key for the given hierarchy: 0x%x", hierarchy)
	}
}

func writeKey(debug, out io.Writer, pubKey crypto.PublicKey) error {
	fmt.Fprintf(debug, "Got key: %+v\n", pubKey)
	asn1Bytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return err
	}

	return pem.Encode(out, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	})
}

func readTPMTPublic(rw io.Reader) (*directtpm2.TPMTPublic, error) {
	data, err := io.ReadAll(rw)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key: %v", err)
	}
	tPublic, err := directtpm2.Unmarshal[directtpm2.TPMTPublic](data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal public area: %v", err)
	}
	return tPublic, nil
}
