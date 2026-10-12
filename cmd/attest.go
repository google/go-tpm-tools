package cmd

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"

	"cloud.google.com/go/compute/metadata"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"
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
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := parseAttestFlags(cmd)
		if err != nil {
			return err
		}

		rwc, err := openTpm()
		if err != nil {
			return err
		}
		defer rwc.Close()

		attestation, err := RunAttest(cmd.Context(), rwc, cfg.opts)
		if err != nil {
			return err
		}

		out, err := formatAttestation(attestation, cfg.format)
		if err != nil {
			return err
		}

		if cfg.outputPath != "" {
			return os.WriteFile(cfg.outputPath, out, 0644)
		}
		_, err = cmd.OutOrStdout().Write(out)
		return err
	},
}

// AttestOptions configures the attestation report generation.
type AttestOptions struct {
	Key           string
	KeyAlgo       tpm2.Algorithm
	Nonce         []byte
	TEENonce      []byte
	TEETechnology string
}

type attestCmdConfig struct {
	opts       AttestOptions
	format     string
	outputPath string
}

func parseAttestFlags(cmd *cobra.Command) (attestCmdConfig, error) {
	flags := cmd.Flags()
	var cfg attestCmdConfig

	var err error
	cfg.opts.Key, err = flags.GetString("key")
	if err != nil {
		return attestCmdConfig{}, err
	}
	if cfg.opts.Key != "AK" && cfg.opts.Key != "gceAK" {
		return attestCmdConfig{}, fmt.Errorf("key should be either AK or gceAK")
	}

	if flags.Changed("algo") {
		if f := flags.Lookup("algo"); f != nil && f.Value.String() != "" {
			switch val := f.Value.String(); val {
			case "rsa":
				cfg.opts.KeyAlgo = tpm2.AlgRSA
			case "ecc":
				cfg.opts.KeyAlgo = tpm2.AlgECC
			default:
				return attestCmdConfig{}, fmt.Errorf("unsupported key algorithm: %s", val)
			}
		}
	} else {
		cfg.opts.KeyAlgo = tpm2.AlgRSA
	}

	cfg.opts.Nonce, err = flags.GetBytesHex("nonce")
	if err != nil {
		return attestCmdConfig{}, err
	}

	cfg.opts.TEENonce, err = flags.GetBytesHex("tee-nonce")
	if err != nil {
		return attestCmdConfig{}, err
	}

	cfg.opts.TEETechnology, err = flags.GetString("tee-technology")
	if err != nil {
		return attestCmdConfig{}, err
	}

	cfg.format, err = flags.GetString("format")
	if err != nil {
		return attestCmdConfig{}, err
	}
	if cfg.format != "binarypb" && cfg.format != "textproto" {
		return attestCmdConfig{}, fmt.Errorf("format should be either binarypb or textproto")
	}

	cfg.outputPath, err = flags.GetString("output")
	if err != nil {
		return attestCmdConfig{}, err
	}

	return cfg, nil
}

// RunAttest generates an attestation report using the provided TPM.
func RunAttest(ctx context.Context, rwc io.ReadWriter, opts AttestOptions) (*attest.Attestation, error) {
	if opts.Key == "" {
		opts.Key = "AK"
	}
	if opts.KeyAlgo == 0 {
		opts.KeyAlgo = tpm2.AlgRSA
	}

	attestationKey, err := createAttestationKey(rwc, opts.Key, opts.KeyAlgo)
	if err != nil {
		return nil, fmt.Errorf("failed to create attestation key: %w", err)
	}
	defer attestationKey.Close()

	attestOpts := client.AttestOpts{
		Nonce: opts.Nonce,
	}

	if len(opts.TEENonce) != 0 && opts.TEETechnology == "" {
		return nil, fmt.Errorf("use of --tee-nonce requires specifying TEE hardware type with --tee-technology")
	}

	attestOpts.TEEDevice, err = getTEEDeviceFromTech(opts.TEETechnology)
	if err != nil {
		return nil, err
	}
	if attestOpts.TEEDevice != nil {
		defer attestOpts.TEEDevice.Close()
		attestOpts.TEENonce = opts.TEENonce
	}

	attestOpts.TCGEventLog, err = client.GetEventLog(rwc)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve TCG Event Log: %w", err)
	}

	attestation, err := attestationKey.Attest(attestOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to collect attestation report: %w", err)
	}

	if opts.Key == "gceAK" {
		instanceInfo, err := getInstanceInfoFromMetadata(ctx)
		if err != nil {
			log.Printf("Could not get GCE instance info, continuing without it: %v", err)
		}
		attestation.InstanceInfo = instanceInfo
	}

	return attestation, nil
}

func formatAttestation(attestation *attest.Attestation, format string) ([]byte, error) {
	switch format {
	case "binarypb":
		out, err := proto.Marshal(attestation)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal attestation proto: %w", err)
		}
		return out, nil
	case "textproto":
		return []byte(marshalOptions.Format(attestation)), nil
	default:
		return nil, fmt.Errorf("format should be either binarypb or textproto")
	}
}

func createAttestationKey(rw io.ReadWriter, keyType string, algo tpm2.Algorithm) (*client.Key, error) {
	switch keyType {
	case "AK":
		switch algo {
		case tpm2.AlgRSA:
			return client.AttestationKeyRSA(rw)
		case tpm2.AlgECC:
			return client.AttestationKeyECC(rw)
		}
	case "gceAK":
		switch algo {
		case tpm2.AlgRSA:
			return client.GceAttestationKeyRSA(rw)
		case tpm2.AlgECC:
			return client.GceAttestationKeyECC(rw)
		}
	default:
		return nil, fmt.Errorf("key should be either AK or gceAK")
	}
	return nil, fmt.Errorf("unsupported key algorithm: %v", algo)
}

func getInstanceInfoFromMetadata(ctx context.Context) (*attest.GCEInstanceInfo, error) {
	var err error
	instanceInfo := &attest.GCEInstanceInfo{}

	instanceInfo.ProjectId, err = metadata.ProjectIDWithContext(ctx)
	if err != nil {
		return nil, err
	}

	projectNumber, err := metadata.NumericProjectIDWithContext(ctx)
	if err != nil {
		return nil, err
	}
	instanceInfo.ProjectNumber, err = strconv.ParseUint(projectNumber, 10, 64)
	if err != nil {
		return nil, err
	}

	instanceInfo.Zone, err = metadata.ZoneWithContext(ctx)
	if err != nil {
		return nil, err
	}

	instanceID, err := metadata.InstanceIDWithContext(ctx)
	if err != nil {
		return nil, err
	}
	instanceInfo.InstanceId, err = strconv.ParseUint(instanceID, 10, 64)
	if err != nil {
		return nil, err
	}

	instanceInfo.InstanceName, err = metadata.InstanceNameWithContext(ctx)
	if err != nil {
		return nil, err
	}

	return instanceInfo, err
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
	attestCmd.AddCommand(attestSVSMCmd)
}
