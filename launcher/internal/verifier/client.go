// Package verifier contains clients for various attestation verifiers.
package verifier

import (
	"context"

	"github.com/google/go-tpm-tools/proto/attest"
)

// Client is a common interface to various attestation verifiers.
type Client interface {
	CreateChallenge(ctx context.Context) (*Challenge, error)
	VerifyAttestation(ctx context.Context, request VerifyAttestationRequest) (*VerifyAttestationResponse, error)
}

// Challenge is the response for CreateChallenge. It is used in the
// get challenge part of a remote attestation protocol. The challenge
// will be verified as part of VerifyAttestation.
type Challenge struct {
	Name   string
	Nonce  []byte
	connID string
}

// VerifyAttestationRequest is passed in on VerifyAttestation. It contains the
// Challenge from CreateChallenge, optional GcpCredentials linked to the
// attestation, and the Attestation generated from the TPM.
type VerifyAttestationRequest struct {
	Challenge      *Challenge
	GcpCredentials [][]byte
	Attestation    *attest.Attestation
}

// VerifyAttestationResponse is the response from a successful
// VerifyAttestation call.
type VerifyAttestationResponse struct {
	ClaimsToken []byte
}
