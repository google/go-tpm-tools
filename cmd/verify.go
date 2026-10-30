package cmd

import (
	"crypto"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/google/go-sev-guest/proto/sevsnp"
	sv "github.com/google/go-sev-guest/verify"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	tv "github.com/google/go-tdx-guest/verify"
	pb "github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"
)

func newVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a remote attestation report.",
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newDebugCmd())
	return cmd
}

func newDebugCmd() *cobra.Command {
	var cfg verifyDebugConfig
	cmd := &cobra.Command{
		Use:   "debug",
		Short: "Debug the contents of an attestation report without verifying its root-of-trust (e.g., attestation key certificate). For debugging purposes only",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := checkFormat(cfg.format); err != nil {
				return err
			}

			attestationBytes, err := readAttestationInput(cmd, cfg.inputPath)
			if err != nil {
				return err
			}
			attestation := &pb.Attestation{}

			switch cfg.format {
			case "binarypb":
				err = proto.Unmarshal(attestationBytes, attestation)
			case "textproto":
				err = unmarshalOptions.Unmarshal(attestationBytes, attestation)
			}
			if err != nil {
				return fmt.Errorf("fail to unmarshal attestation report: %w", err)
			}

			ms, err := runVerify(attestation, cfg.tpmNonce, teeNonceOrDefault(cfg.teeNonce, cfg.tpmNonce))
			if err != nil {
				return err
			}
			out, err := marshalOptions.Marshal(ms)
			if err != nil {
				return fmt.Errorf("failed to marshal machine state: %w", err)
			}
			if err := writeVerifyOutput(cmd, cfg.outputPath, out); err != nil {
				return fmt.Errorf("failed to write verified attestation report: %w", err)
			}
			return nil
		},
	}
	addVerifyDebugFlags(cmd, &cfg)
	cmd.AddCommand(newVerifySVSMCmd(&cfg))
	return cmd
}

type verifyDebugConfig struct {
	tpmNonce            []byte
	teeNonce            []byte
	format              string
	inputPath           string
	outputPath          string
	certifiedAKBlobPath string
}

func addVerifyDebugFlags(cmd *cobra.Command, cfg *verifyDebugConfig) {
	flags := cmd.PersistentFlags()
	flags.BytesHexVar(&cfg.tpmNonce, "nonce", []byte{}, "hex encoded nonce for vTPM attestation, cannot be empty")
	flags.StringVar(&cfg.outputPath, "output", "", "output file (defaults to stdout)")
	flags.StringVar(&cfg.inputPath, "input", "", "input file (defaults to stdin)")
	flags.StringVar(&cfg.format, "format", "binarypb", "type of output file where attestation report stored <binarypb|textproto>")
	flags.BytesHexVar(&cfg.teeNonce, "tee-nonce", []byte{}, "hex encoded teenonce for hardware attestation, can be empty")
	flags.StringVar(&cfg.certifiedAKBlobPath, "certified-ak-blob", "",
		"Specify path to certified AK blob produced from TPM registration. "+
			"Required for manifest version 0 and rejected for manifest version 1, where the "+
			"AK is taken from --input.")
}

func teeNonceOrDefault(teeNonce, nonce []byte) []byte {
	if len(teeNonce) == 0 {
		return nonce
	}
	return teeNonce
}

var errUnknownFormat = errors.New("format should be either binarypb or textproto")

func checkFormat(format string) error {
	if format != "binarypb" && format != "textproto" {
		return errUnknownFormat
	}
	return nil
}

func readAttestationInput(cmd *cobra.Command, path string) ([]byte, error) {
	if path == "" {
		return io.ReadAll(cmd.InOrStdin())
	}
	return os.ReadFile(path)
}

func writeVerifyOutput(cmd *cobra.Command, path string, out []byte) error {
	if path == "" {
		_, err := cmd.OutOrStdout().Write(out)
		return err
	}
	return os.WriteFile(path, out, 0644)
}

// Callers must pass the resolved teeNonce.
func runVerify(attestation *pb.Attestation, tpmNonce, teeNonce []byte) (*pb.MachineState, error) {
	pub, err := tpm2.DecodePublic(attestation.GetAkPub())
	if err != nil {
		return nil, err
	}
	cryptoPub, err := pub.Key()
	if err != nil {
		return nil, err
	}

	// TODO(#524): create separate, discrete subcommands that verifies SNP and TDX attestation.
	ms, err := server.VerifyAttestation(attestation, server.VerifyOpts{
		Nonce:      tpmNonce,
		TrustedAKs: []crypto.PublicKey{cryptoPub},
	})
	if err != nil {
		return nil, fmt.Errorf("verifying TPM attestation: %w", err)
	}
	if err := verifyGceTechnology(attestation, teeNonce); err != nil {
		return nil, fmt.Errorf("verifying TEE attestation: %w", err)
	}
	teeMS, err := parseTEEAttestation(attestation, ms.GetPlatform().Technology)
	if err != nil {
		return nil, fmt.Errorf("failed to parse machineState from TEE attestation: %w", err)
	}
	ms.TeeAttestation = teeMS.TeeAttestation
	return ms, nil
}

// parseTEEAttestation parses a machineState from TeeAttestation.
// For now it simply populates the machineState TeeAttestation field with the verified TDX/SNP data.
// In long term, it should parse a full machineState from TeeAttestation.
func parseTEEAttestation(attestation *pb.Attestation, tech pb.GCEConfidentialTechnology) (*pb.MachineState, error) {
	switch tech {
	case pb.GCEConfidentialTechnology_AMD_SEV_SNP:
		tee, ok := attestation.TeeAttestation.(*pb.Attestation_SevSnpAttestation)
		if !ok {
			return nil, fmt.Errorf("TEE attestation is %T, expected a SevSnpAttestation", attestation.GetTeeAttestation())
		}
		return &pb.MachineState{
			TeeAttestation: &pb.MachineState_SevSnpAttestation{
				SevSnpAttestation: proto.Clone(tee.SevSnpAttestation).(*sevsnp.Attestation),
			}}, nil
	case pb.GCEConfidentialTechnology_INTEL_TDX:
		tee, ok := attestation.TeeAttestation.(*pb.Attestation_TdxAttestation)
		if !ok {
			return nil, fmt.Errorf("TEE attestation is %T, expected a TdxAttestation", attestation.GetTeeAttestation())
		}
		return &pb.MachineState{
			TeeAttestation: &pb.MachineState_TdxAttestation{
				TdxAttestation: proto.Clone(tee.TdxAttestation).(*tdxpb.QuoteV4),
			}}, nil
	default:
		return &pb.MachineState{}, nil
	}
}

func verifyGceTechnology(attestation *pb.Attestation, teeNonce []byte) error {
	if attestation.GetTeeAttestation() == nil {
		return nil
	}
	switch attestation.GetTeeAttestation().(type) {
	case *pb.Attestation_TdxAttestation:
		tdxOpts := &verifyTdxOpts{
			Validation:   tdxDefaultValidateOpts(teeNonce),
			Verification: tv.DefaultOptions(),
		}
		tee, ok := attestation.TeeAttestation.(*pb.Attestation_TdxAttestation)
		if !ok {
			return fmt.Errorf("TEE attestation is %T, expected a TdxAttestation", attestation.GetTeeAttestation())
		}
		return verifyTdxAttestation(tee.TdxAttestation, tdxOpts)
	case *pb.Attestation_SevSnpAttestation:
		snpOpts := &verifySnpOpts{
			Validation:   sevSnpDefaultValidateOpts(teeNonce),
			Verification: &sv.Options{},
		}
		tee, ok := attestation.TeeAttestation.(*pb.Attestation_SevSnpAttestation)
		if !ok {
			return fmt.Errorf("TEE attestation is %T, expected a SevSnpAttestation", attestation.GetTeeAttestation())
		}
		return verifySevSnpAttestation(tee.SevSnpAttestation, snpOpts)
	default:
		return fmt.Errorf("unknown attestation type: %T", attestation.GetTeeAttestation())
	}
}
