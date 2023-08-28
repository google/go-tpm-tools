package cmd

import (
	"fmt"
	"io"
	"strconv"

	"cloud.google.com/go/compute/metadata"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"
)

var (
	key           string
	teeTechnology string
)

// Add constants for other devices when required
const (
	// SevSnp is a constant denotes device name for teeTechnology
	SevSnp = "sev-snp"
	// Tdx is a constant denotes device name for teeTechnology
	Tdx = "tdx"
)

var attestationKeys = map[string]map[tpm2.Algorithm]func(rw io.ReadWriter) (*client.Key, error){
	"AK": {
		tpm2.AlgRSA: client.AttestationKeyRSA,
		tpm2.AlgECC: client.AttestationKeyECC,
	},
	"gceAK": {
		tpm2.AlgRSA: client.GceAttestationKeyRSA,
		tpm2.AlgECC: client.GceAttestationKeyECC,
	},
}

// If hardware technology needs a variable length teenonce then please modify the flags description
var attestCmd = &cobra.Command{
	Use:   "attest",
	Short: "Create a remote attestation report",
	Long: `Gather information for remote attestation.
The Attestation report contains a quote on all available PCR banks, a way to validate 
the quote, and a TCG Event Log (Linux only).
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

		if !(format == "binarypb" || format == "textproto") {
			return fmt.Errorf("format should be either binarypb or textproto")
		}

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

		var out []byte
		if format == "binarypb" {
			out, err = proto.Marshal(attestation)
			if err != nil {
				return fmt.Errorf("failed to marshal attestation proto: %v", attestation)
			}
		} else {
			out = []byte(marshalOptions.Format(attestation))
		}
		if _, err := dataOutput().Write(out); err != nil {
			return fmt.Errorf("failed to write attestation report: %v", err)
		}
		return nil
	},
}

func getInstanceInfoFromMetadata() (*attest.GCEInstanceInfo, error) {

	var err error
	instanceInfo := &attest.GCEInstanceInfo{}

	instanceInfo.ProjectId, err = metadata.ProjectID()
	if err != nil {
		return nil, err
	}

	projectNumber, err := metadata.NumericProjectID()
	if err != nil {
		return nil, err
	}
	instanceInfo.ProjectNumber, err = strconv.ParseUint(projectNumber, 10, 64)
	if err != nil {
		return nil, err
	}

	instanceInfo.Zone, err = metadata.Zone()
	if err != nil {
		return nil, err
	}

	instanceID, err := metadata.InstanceID()
	if err != nil {
		return nil, err
	}
	instanceInfo.InstanceId, err = strconv.ParseUint(instanceID, 10, 64)
	if err != nil {
		return nil, err
	}

	instanceInfo.InstanceName, err = metadata.InstanceName()
	if err != nil {
		return nil, err
	}

	return instanceInfo, err
}

func addKeyFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&key, "key", "AK", "indicates type of attestation key to use <gceAK|AK>")
}

func addTeeTechnology(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&teeTechnology, "tee-technology", "", "indicates the type of TEE hardware. Should be either empty or one of sev-snp or tdx")
}

func init() {
	RootCmd.AddCommand(attestCmd)
	addKeyFlag(attestCmd)
	addNonceFlag(attestCmd)
	addTeeNonceflag(attestCmd)
	addPublicKeyAlgoFlag(attestCmd)
	addOutputFlag(attestCmd)
	addFormatFlag(attestCmd)
	addTeeTechnology(attestCmd)
}
