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
	name   string
	nonce  []byte
	connID string
}

// Name is the attestation verifier-specific identifier for a challenge.
func (c Challenge) Name() string {
	return c.name
}

// Nonce is attestation verifier-generated random data used when generating a
// TPM quote.
func (c Challenge) Nonce() []byte {
	return c.nonce
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
	claimsToken []byte
}

// ClaimsToken is the OIDC token issued by the attestation verifier on a
// successful VerifyAttestation call. It contains attestation-derived claims
// about the platform.
func (r VerifyAttestationResponse) ClaimsToken() []byte {
	return r.claimsToken
}
