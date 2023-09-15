package cmd

import (
	"fmt"

	"github.com/google/go-tpm-tools/client"
	"github.com/spf13/cobra"
)

// If hardware technology needs a variable length teenonce then please modify the flags description
var gentokenCmd = &cobra.Command{
	Use:   "gentoken",
	Short: "Attest and fetch an OIDC token from Google Attestation Verification Service",
	Long: `Gather attestation report and send it to Google Attestation Verification Service for an OIDC token.
The Attestation report contains a quote on all available PCR banks, a way to validate 
the quote, and a TCG Event Log (Linux only). The OIDC token includes claims regarding the authentication of the user by the authorization server (Google IAM server) with the use of an OAuth client application(Google Cloud apps).
Use --key to specify the type of attestation key. It can be gceAK for GCE attestation
key or AK for a custom attestation key. By default it uses AK.
--algo flag overrides the public key algorithm for attestation key. If not provided then
by default rsa is used.
--tee-nonce attaches a 64 bytes extra data to the attestation report of TDX and SEV-SNP 
hardware and guarantees a fresh quote.
`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		rwc, err := openTpm()
		if err != nil {
			return err
		}
		defer rwc.Close()

		var attestationKey *client.Key
		algoToCreateAK, ok := attestationKeys[key]
		if !ok {
			return fmt.Errorf("key should be either AK or gceAK")
		}
		createFunc := algoToCreateAK[keyAlgo]
		attestationKey, err = createFunc(rwc)
		if err != nil {
			return fmt.Errorf("failed to create attestation key: %v", err)
		}
		defer attestationKey.Close()

		attestOpts := client.AttestOpts{}
		attestOpts.Nonce = nonce

		// Add logic to open other hardware devices when required.
		switch teeTechnology {
		case SevSnp:
			attestOpts.TEEDevice, err = client.CreateSevSnpDevice()
			if err != nil {
				return fmt.Errorf("failed to open %s device: %v", SevSnp, err)
			}
			attestOpts.TEENonce = teeNonce
		case Tdx:
			attestOpts.TEEDevice, err = client.CreateTdxDevice()
			if err != nil {
				return fmt.Errorf("failed to open %s device: %v", Tdx, err)
			}
			attestOpts.TEENonce = teeNonce
		case "":
			if len(teeNonce) != 0 {
				return fmt.Errorf("use of --tee-nonce requires specifying TEE hardware type with --tee-technology")
			}
		default:
			// Change the return statement when more devices are added
			return fmt.Errorf("tee-technology should be either empty or should have values %s or %s", SevSnp, Tdx)
		}

		attestOpts.TCGEventLog, err = client.GetEventLog(rwc)
		if err != nil {
			return fmt.Errorf("failed to retrieve TCG Event Log: %w", err)
		}

		attestation, err := attestationKey.Attest(attestOpts)
		if err != nil {
			return fmt.Errorf("failed to collect attestation report : %v", err)
		}

		if key == "gceAK" {
			instanceInfo, err := getInstanceInfoFromMetadata()
			if err != nil {
				return err
			}
			attestation.InstanceInfo = instanceInfo
		}
		return nil
	},
}

func init() {
	RootCmd.AddCommand(gentokenCmd)
	addKeyFlag(gentokenCmd)
	addNonceFlag(gentokenCmd)
	addTeeNonceflag(gentokenCmd)
	addPublicKeyAlgoFlag(gentokenCmd)
	addOutputFlag(gentokenCmd)
	addTeeTechnology(gentokenCmd)
}
