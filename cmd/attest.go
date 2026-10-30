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

// If hardware technology needs a variable length teenonce then please modify the flags description
func newAttestCmd(e *env) *cobra.Command {
	var cfg attestCmdConfig
	cmd := &cobra.Command{
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
			if err := cfg.validate(); err != nil {
				return err
			}

			rwc, err := e.openTpm()
			if err != nil {
				return err
			}
			defer rwc.Close()

			attestation, err := runAttest(cmd.Context(), rwc, cfg.opts)
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
	addAttestFlags(cmd, &cfg)
	cmd.AddCommand(newAttestSVSMCmd(e, &cfg))
	return cmd
}

// attestOptions configures the attestation report generation.
type attestOptions struct {
	key           string
	keyAlgo       tpm2.Algorithm
	nonce         []byte
	teeNonce      []byte
	teeTechnology string
}

type attestCmdConfig struct {
	opts       attestOptions
	format     string
	outputPath string
}

func addAttestFlags(cmd *cobra.Command, cfg *attestCmdConfig) {
	cmd.PersistentFlags().StringVar(&cfg.opts.key, "key", "AK", "indicates type of attestation key to use <gceAK|AK>")
	addPublicKeyAlgoFlag(cmd, &cfg.opts.keyAlgo)
	addNonceFlag(cmd, &cfg.opts.nonce)
	addTeeNonceflag(cmd, &cfg.opts.teeNonce)
	addTeeTechnology(cmd, &cfg.opts.teeTechnology)
	addFormatFlag(cmd, &cfg.format)
	addOutputFlag(cmd, &cfg.outputPath)
}

func (c *attestCmdConfig) validate() error {
	if c.opts.key != "AK" && c.opts.key != "gceAK" {
		return fmt.Errorf("key should be either AK or gceAK")
	}
	if c.format != "binarypb" && c.format != "textproto" {
		return fmt.Errorf("format should be either binarypb or textproto")
	}
	return nil
}

// runAttest generates an attestation report using the provided TPM.
func runAttest(ctx context.Context, rwc io.ReadWriter, opts attestOptions) (*attest.Attestation, error) {
	if opts.key == "" {
		opts.key = "AK"
	}
	if opts.keyAlgo == tpm2.AlgUnknown {
		opts.keyAlgo = tpm2.AlgRSA
	}

	attestationKey, err := createAttestationKey(rwc, opts.key, opts.keyAlgo)
	if err != nil {
		return nil, fmt.Errorf("failed to create attestation key: %w", err)
	}
	defer attestationKey.Close()

	attestOpts := client.AttestOpts{
		Nonce: opts.nonce,
	}

	if len(opts.teeNonce) != 0 && opts.teeTechnology == "" {
		return nil, fmt.Errorf("use of --tee-nonce requires specifying TEE hardware type with --tee-technology")
	}

	attestOpts.TEEDevice, err = getTEEDeviceFromTech(opts.teeTechnology)
	if err != nil {
		return nil, err
	}
	if attestOpts.TEEDevice != nil {
		defer attestOpts.TEEDevice.Close()
		attestOpts.TEENonce = opts.teeNonce
	}

	attestOpts.TCGEventLog, err = client.GetEventLog(rwc)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve TCG Event Log: %w", err)
	}

	attestation, err := attestationKey.Attest(attestOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to collect attestation report: %w", err)
	}

	if opts.key == "gceAK" {
		instanceInfo, err := getInstanceInfoFromMetadata(ctx)
		if err != nil {
			log.Printf("Could not get GCE instance info, continuing without it: %v", err)
		}
		attestation.InstanceInfo = instanceInfo
	}

	return attestation, nil
}

func formatAttestation(attestation *attest.Attestation, outFormat string) ([]byte, error) {
	switch outFormat {
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
