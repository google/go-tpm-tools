package cmd

import (
	"crypto"
	"fmt"
	"io"

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

		if format == "binarypb" {
			err = proto.Unmarshal(attestationBytes, attestation)
		} else if format == "textproto" {
			err = unmarshalOptions.Unmarshal(attestationBytes, attestation)
		} else {
			return fmt.Errorf("format should be either binarypb or textproto")
		}
		if err != nil {
			return fmt.Errorf("fail to unmarshal attestation report: %v", err)
		}

		pub, err := tpm2.DecodePublic(attestation.GetAkPub())
		if err != nil {
			return err
		}
		cryptoPub, err := pub.Key()
		if err != nil {
			return err
		}

		// TODO(#524): create a new subcommand that verifies SNP and TDX attestation.
		ms, err := server.VerifyAttestation(attestation, server.VerifyOpts{Nonce: nonce, TrustedAKs: []crypto.PublicKey{cryptoPub}})
		if err != nil {
			return fmt.Errorf("verifying attestation: %w", err)
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

func init() {
	RootCmd.AddCommand(verifyCmd)
	verifyCmd.AddCommand(debugCmd)
	addNonceFlag(debugCmd)
	addOutputFlag(debugCmd)
	addInputFlag(debugCmd)
	addFormatFlag(debugCmd)
	addTeeNonceflag(debugCmd)
}
