// Package fake is a fake implementation of the Client interface for testing.
package fake

import (
	"context"
	"crypto"
	"encoding/binary"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/go-tpm-tools/launcher/verifier"
)

type fakeClient struct {
	signer crypto.Signer
}

// NewClient contructs a new fake client given a crypto.Signer.
func NewClient(signer crypto.Signer) verifier.Client {
	return &fakeClient{signer}
}

// CreateChallenge returns a hard coded, basic challenge.
//
// If you have found this method is insufficient for your tests, this class must be updated to
// allow for better testing.
func (fc *fakeClient) CreateChallenge(ctx context.Context) (*verifier.Challenge, error) {
	bs := make([]byte, 2)
	binary.LittleEndian.PutUint16(bs, 15)
	return &verifier.Challenge{
		Name:  "projects/fakeProject/locations/fakeRegion/challenges/d882c62f-452f-4709-9335-0cccaf64eee1",
		Nonce: bs,
	}, nil
}

// VerifyAttestation does basic checks and returns a hard coded attestation response.
//
// If you have found this method is insufficient for your tests, this class must be updated to
// allow for better testing.
func (fc *fakeClient) VerifyAttestation(ctx context.Context, request verifier.VerifyAttestationRequest) (*verifier.VerifyAttestationResponse, error) {
	// Determine signing algorithm.
	signingMethod := jwt.SigningMethodRS256
	now := jwt.TimeFunc()
	claims := jwt.RegisteredClaims{
		IssuedAt:  &jwt.NumericDate{Time: now},
		NotBefore: &jwt.NumericDate{Time: now},
		ExpiresAt: &jwt.NumericDate{Time: now.Add(time.Hour)},
		Audience:  []string{"https://sts.googleapis.com/"},
		Issuer:    "https://confidentialcomputing.googleapis.com/",
		Subject:   "https://www.googleapis.com/compute/v1/projects/fakeProject/zones/fakeZone/instances/fakeInstance",
	}

	token := jwt.NewWithClaims(signingMethod, claims)

	// Instead of a private key, provide the signer.
	signed, err := token.SignedString(fc.signer)
	if err != nil {
		return nil, err
	}

	response := verifier.VerifyAttestationResponse{
		ClaimsToken: []byte(signed),
	}

	return &response, nil
}
