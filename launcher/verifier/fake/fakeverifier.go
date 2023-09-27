// Package fake is a fake implementation of the Client interface for testing.
package fake

import (
	"context"
	"crypto"
	"encoding/binary"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/go-tpm-tools/launcher/internal/oci"
	"github.com/google/go-tpm-tools/launcher/verifier"
	"go.uber.org/multierr"
	"google.golang.org/genproto/googleapis/rpc/code"
	"google.golang.org/genproto/googleapis/rpc/status"
)

type fakeClient struct {
	signer crypto.Signer
}

// NewClient constructs a new fake client given a crypto.Signer.
func NewClient(signer crypto.Signer) verifier.Client {
	return &fakeClient{signer}
}

// CreateChallenge returns a hard coded, basic challenge.
//
// If you have found this method is insufficient for your tests, this class must be updated to
// allow for better testing.
func (fc *fakeClient) CreateChallenge(_ context.Context) (*verifier.Challenge, error) {
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
func (fc *fakeClient) VerifyAttestation(_ context.Context, req verifier.VerifyAttestationRequest) (*verifier.VerifyAttestationResponse, error) {
	// Determine signing algorithm.
	signingMethod := jwt.SigningMethodRS256
	now := jwt.TimeFunc()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  &jwt.NumericDate{Time: now},
			NotBefore: &jwt.NumericDate{Time: now},
			ExpiresAt: &jwt.NumericDate{Time: now.Add(time.Hour)},
			Audience:  []string{"https://sts.googleapis.com/"},
			Issuer:    "https://confidentialcomputing.googleapis.com/",
			Subject:   "https://www.googleapis.com/compute/v1/projects/fakeProject/zones/fakeZone/instances/fakeInstance",
		},
	}

	var signatureClaims []ContainerImageSignatureClaims
	var partialErrs []*status.Status
	for _, signature := range req.ContainerImageSignatures {
		sc, err := verifyContainerImageSignature(signature)
		if err != nil {
			partialErrs = append(partialErrs, &status.Status{Code: int32(code.Code_INVALID_ARGUMENT), Message: err.Error()})
		} else {
			signatureClaims = append(signatureClaims, sc)
		}
	}
	claims.ContainerImageSignatures = signatureClaims

	token := jwt.NewWithClaims(signingMethod, claims)

	// Instead of a private key, provide the signer.
	signed, err := token.SignedString(fc.signer)
	if err != nil {
		return nil, err
	}

	response := verifier.VerifyAttestationResponse{
		ClaimsToken: []byte(signed),
		PartialErrs: partialErrs,
	}

	return &response, nil
}

func verifyContainerImageSignature(signature oci.Signature) (ContainerImageSignatureClaims, error) {
	var err error
	payload, e := signature.Payload()
	if e != nil {
		err = multierr.Append(err, e)
	}
	b64Sig, e := signature.Base64Encoded()
	if e != nil {
		err = multierr.Append(err, e)
	}
	pubKey, e := signature.PublicKey()
	if e != nil {
		err = multierr.Append(err, e)
	}
	sigAlg, e := signature.SigningAlgorithm()
	if e != nil {
		err = multierr.Append(err, e)
	}
	return ContainerImageSignatureClaims{
		Payload:   string(payload),
		Signature: b64Sig,
		PubKey:    string(pubKey),
		SigAlg:    string(sigAlg),
	}, err
}
