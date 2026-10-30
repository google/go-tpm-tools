package cmd

import (
	"fmt"

	"github.com/google/go-tpm-tools/client"
	tpb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm-tools/server"
	tpm2legacy "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/spf13/cobra"
)

// This file implements TPM registration which for now is only used for SVSM e-vTPMs.
// It uses https://trustedcomputinggroup.org/wp-content/uploads/EK-Based-Key-Attestation-with-TPM-Firmware-Version-V1-RC1_9July2025.pdf#page=8
// which we call as import certify.
// ActivateCredential is not implemented yet.

func newRegisterCmd(e *env) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register an SVSM TPM AK",
		Long:  "Given an EK, we'll register a corresponding AK and prove that it's on the same TPM as the EK.",
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newCreateChallengeCmd(), newSolveChallengeCmd(e), newVerifyChallengeCmd())
	return cmd
}

func addSecretInputFlag(cmd *cobra.Command, secretIn *string) {
	cmd.PersistentFlags().StringVar(secretIn, "secret-input", "",
		"specifies path to read the secret that was generated from create-challenge")
}

func addSecretOutputFlag(cmd *cobra.Command, secretOut *string) {
	cmd.PersistentFlags().StringVar(secretOut, "secret-output", "",
		"specifies path to write the secret to")
}

func newCreateChallengeCmd() *cobra.Command {
	var (
		input, output, format string
		secretOut             string
	)
	cmd := &cobra.Command{
		Use:   "create-challenge",
		Short: "Create a challenge for the client to register the EK",
		Long: `Given an EK public key in TPM2 wire format, create a challenge for the client
	to register the EK.  and save the ChallengeSecret but don't share it with the
	client.`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			ekpub, err := readTPMTPublic(dataInput(input))
			if err != nil {
				return err
			}

			challenge, secret, err := server.CreateRestrictedHMACBlob(ekpub)
			if err != nil {
				return fmt.Errorf("could not create challenge: %s", err)
			}
			if err := writeProtoToOutput(challenge, format, output); err != nil {
				return fmt.Errorf("could not write challenge: %w", err)
			}
			_, err = openForWrite(secretOut).Write(secret)
			if err != nil {
				return fmt.Errorf("could not write secret: %s", err)
			}

			return nil
		},
	}
	addOutputFlag(cmd, &output)
	addFormatFlag(cmd, &format)
	addInputFlag(cmd, &input)
	addSecretOutputFlag(cmd, &secretOut)
	return cmd
}

func newSolveChallengeCmd(e *env) *cobra.Command {
	var (
		input, output, format string
		keyAlgo               tpm2legacy.Algorithm
	)
	cmd := &cobra.Command{
		Use:   "solve-challenge",
		Short: "Solve a challenge from the TPM EK",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			challenge := &tpb.ImportBlob{}
			err := readProtoFromPath(input, challenge)
			if err != nil {
				return fmt.Errorf("could not read challenge: %s", err)
			}

			rwc, err := e.openTpm()
			if err != nil {
				return fmt.Errorf("could not open TPM: %s", err)
			}
			defer rwc.Close()
			tpm := transport.FromReadWriter(rwc)
			solved, err := client.CreateCertifiedAKBlob(tpm, challenge, tpm2.TPMAlgID(keyAlgo))
			if err != nil {
				return fmt.Errorf("could not solve challenge: %s", err)
			}
			if err := writeProtoToOutput(solved, format, output); err != nil {
				return fmt.Errorf("could not write solved challenge: %w", err)
			}
			return nil
		},
	}
	addOutputFlag(cmd, &output)
	addFormatFlag(cmd, &format)
	addInputFlag(cmd, &input)
	addPublicKeyAlgoFlag(cmd, &keyAlgo)
	return cmd
}

func newVerifyChallengeCmd() *cobra.Command {
	var (
		input, output, format string
		secretIn              string
	)
	cmd := &cobra.Command{
		Use:   "verify-challenge",
		Short: "Verify a challenge for the SVSM TPM's EK and its binding to the SNP attestation report",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			blob := &tpb.CertifiedBlob{}
			err := readProtoFromPath(input, blob)
			if err != nil {
				return err
			}

			if secretIn == "" {
				return fmt.Errorf("secret-input must be specified")
			}
			secret, err := readBytes(secretIn)
			if err != nil {
				return fmt.Errorf("could not read secret: %s", err)
			}

			err = server.VerifyCertifiedAKBlob(blob, secret)
			if err != nil {
				return fmt.Errorf("could not verify attestation: %s", err)
			}
			return nil
		},
	}
	addOutputFlag(cmd, &output)
	addFormatFlag(cmd, &format)
	addInputFlag(cmd, &input)
	addSecretInputFlag(cmd, &secretIn)
	return cmd
}
