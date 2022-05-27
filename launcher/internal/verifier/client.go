package verifier

import (
	"context"

	"github.com/google/go-tpm-tools/proto/attest"
)

type Client interface {
	CreateChallenge(ctx context.Context) (*Challenge, error)
	VerifyAttestation(ctx context.Context, request VerifyAttestationRequest) (*VerifyAttestationResponse, error)
}

type Challenge struct {
	name   string
	nonce  []byte
	connId string
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

type VerifyAttestationRequest struct {
	Challenge      *Challenge
	GcpCredentials [][]byte
	Attestation    *attest.Attestation
}

type VerifyAttestationResponse struct {
	claimsToken []byte
}

// ClaimsToken is the OIDC token issued by the attestation verifier on a
// successful VerifyAttestation call. It contains attestation-derived claims
// about the platform.
func (r VerifyAttestationResponse) ClaimsToken() []byte {
	return r.claimsToken
}
