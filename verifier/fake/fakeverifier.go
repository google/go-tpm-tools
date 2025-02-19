// Package fake is a fake implementation of the Client interface for testing.
package fake

import (
	"context"
	"crypto"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm-tools/verifier"
	"github.com/google/go-tpm-tools/verifier/oci"
	"github.com/google/go-tpm/legacy/tpm2"
	"google.golang.org/genproto/googleapis/rpc/code"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

type fakeClient struct {
	signer crypto.Signer
	nonce  []byte
}

// NewClient constructs a new fake client given a crypto.Signer.
func NewClient(signer crypto.Signer) verifier.Client {
	nonce := make([]byte, 2)
	binary.LittleEndian.PutUint16(nonce, 15)

	return &fakeClient{signer, nonce}
}

// CreateChallenge returns a hard coded, basic challenge.
//
// If you have found this method is insufficient for your tests, this class must be updated to
// allow for better testing.
func (fc *fakeClient) CreateChallenge(_ context.Context) (*verifier.Challenge, error) {
	return &verifier.Challenge{
		Name:  "projects/fakeProject/locations/fakeRegion/challenges/d882c62f-452f-4709-9335-0cccaf64eee1",
		Nonce: fc.nonce,
	}, nil
}

// VerifyAttestation calls server.VerifyAttestation against the request's public key.
// It returns the marshaled MachineState as a claim.
func (fc *fakeClient) VerifyAttestation(_ context.Context, req verifier.VerifyAttestationRequest) (*verifier.VerifyAttestationResponse, error) {
	// Determine signing algorithm.
	signingMethod := jwt.SigningMethodRS256
	now := jwt.TimeFunc()
	akPub, err := tpm2.DecodePublic(req.Attestation.GetAkPub())
	if err != nil {
		return nil, fmt.Errorf("failed to decode AKPub as TPMT_PUBLIC: %v", err)
	}
	akCrypto, err := akPub.Key()
	if err != nil {
		return nil, fmt.Errorf("failed to convert TPMT_PUBLIC to crypto.PublicKey: %v", err)
	}
	ms, err := server.VerifyAttestation(req.Attestation, server.VerifyOpts{Nonce: fc.nonce, TrustedAKs: []crypto.PublicKey{akCrypto}})
	if err != nil {
		return nil, fmt.Errorf("failed to verify attestation: %v", err)
	}

	msJSON, err := protojson.Marshal(ms)
	if err != nil {
		return nil, fmt.Errorf("failed to convert proto object to JSON: %v", err)
	}
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  &jwt.NumericDate{Time: now},
			NotBefore: &jwt.NumericDate{Time: now},
			ExpiresAt: &jwt.NumericDate{Time: now.Add(time.Hour)},
			Audience:  []string{"https://sts.googleapis.com/"},
			Issuer:    "https://confidentialcomputing.googleapis.com/",
			Subject:   "https://www.googleapis.com/compute/v1/projects/fakeProject/zones/fakeZone/instances/fakeInstance",
		},
		MachineStateMarshaled: string(msJSON),
	}

	var signatureClaims []ContainerImageSignatureClaims
	var partialErrs []*status.Status
	for _, signature := range req.ContainerImageSignatures {
		claims, err := extractClaims(signature)
		if err != nil {
			partialErrs = append(partialErrs, &status.Status{Code: int32(code.Code_INVALID_ARGUMENT), Message: err.Error()})
		} else {
			signatureClaims = append(signatureClaims, claims)
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

type payload struct {
	Optional map[string]any `json:"optional"` // Optional represents optional metadata about the image, and its value shouldn't contain any "=" signs.
}

func isValid(alg string) bool {
	switch alg {
	case string(oci.ECDSAP256SHA256), string(oci.RSASSAPKCS1V152048SHA256), string(oci.RSASSAPSS2048SHA256):
		return true
	default:
		return false
	}
}

// Note: this is only compatible with the fake signature implementation.
func extractClaims(signature oci.Signature) (ContainerImageSignatureClaims, error) {
	payload, err := signature.Payload()
	if err != nil {
		return ContainerImageSignatureClaims{}, err
	}
	payloadStr := string(payload)

	// Fake payload consists of the expected pubkey and sigalg separated by a comma.
	separatorIndex := strings.LastIndex(payloadStr, ",")

	sigAlg := payloadStr[separatorIndex+1:]
	if !isValid(sigAlg) {
		return ContainerImageSignatureClaims{}, fmt.Errorf("unsupported algorithm %v", sigAlg)
	}

	sig, err := signature.Base64Encoded()
	if err != nil {
		return ContainerImageSignatureClaims{}, err
	}

	return ContainerImageSignatureClaims{
		Payload:   payloadStr,
		Signature: sig,
		PubKey:    payloadStr[:separatorIndex],
		SigAlg:    sigAlg,
	}, nil
}
