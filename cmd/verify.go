package cmd

import (
	"crypto"
	"fmt"
	"io"

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

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a remote attestation report.",
	Args:  cobra.NoArgs,
}
var debugCmd = &cobra.Command{
	Use:   "debug",
	Short: "Debug the contents of an attestation report without verifying its root-of-trust (e.g., attestation key certificate). For debugging purposes only",
	RunE: func(*cobra.Command, []string) error {
		attestationBytes, err := io.ReadAll(dataInput())
		if err != nil {
			return err
		}
		attestation := &pb.Attestation{}

		switch format {
		case "binarypb":
			err = proto.Unmarshal(attestationBytes, attestation)
		case "textproto":
			err = unmarshalOptions.Unmarshal(attestationBytes, attestation)
		default:
			return fmt.Errorf("format should be either binarypb or textproto")
		}
		if err != nil {
			return fmt.Errorf("fail to unmarshal attestation report: %v", err)
		}

		ms, err := verifyDebugAttestation(attestation, nonce, teeNonce)
		if err != nil {
			return err
		}
		out, err := marshalOptions.Marshal(ms)
		if err != nil {
			return nil
		}
		if _, err := dataOutput().Write(out); err != nil {
			return fmt.Errorf("failed to write verified attestation report: %v", err)
		}
		return nil
	},
}

func verifyDebugAttestation(attestation *pb.Attestation, tpmNonce, customTEENonce []byte) (*pb.MachineState, error) {
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
	if err := verifyGceTechnology(attestation, tpmNonce, customTEENonce); err != nil {
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

func verifyGceTechnology(attestation *pb.Attestation, tpmNonce, customTEENonce []byte) error {
	if attestation.GetTeeAttestation() == nil {
		return nil
	}
	effectiveNonce := tpmNonce
	if len(customTEENonce) != 0 {
		effectiveNonce = customTEENonce
	}
	switch attestation.GetTeeAttestation().(type) {
	case *pb.Attestation_TdxAttestation:
		tdxOpts := &verifyTdxOpts{
			Validation:   tdxDefaultValidateOpts(effectiveNonce),
			Verification: tv.DefaultOptions(),
		}
		tee, ok := attestation.TeeAttestation.(*pb.Attestation_TdxAttestation)
		if !ok {
			return fmt.Errorf("TEE attestation is %T, expected a TdxAttestation", attestation.GetTeeAttestation())
		}
		return verifyTdxAttestation(tee.TdxAttestation, tdxOpts)
	case *pb.Attestation_SevSnpAttestation:
		snpOpts := &verifySnpOpts{
			Validation:   sevSnpDefaultValidateOpts(effectiveNonce),
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

func init() {
	RootCmd.AddCommand(verifyCmd)
	verifyCmd.AddCommand(debugCmd)
	addNonceFlag(debugCmd)
	addOutputFlag(debugCmd)
	addInputFlag(debugCmd)
	addFormatFlag(debugCmd)
	addTeeNonceflag(debugCmd)
	addCertifiedAKBlobFlag(debugCmd)
	debugCmd.AddCommand(verifySVSMCmd)
	addEKPubFlag(verifySVSMCmd)
	addTeeTechnology(verifySVSMCmd)
}
