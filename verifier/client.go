// Package verifier contains clients for various attestation verifiers.
// It is meant for launcher use and testing; the API is not stable.
package verifier

import (
	"context"

	attestpb "github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm-tools/verifier/models"
	"google.golang.org/genproto/googleapis/rpc/status"
)

// Client is a common interface to various attestation verifiers.
type Client interface {
	CreateChallenge(ctx context.Context) (*Challenge, error)
	VerifyAttestation(ctx context.Context, request VerifyAttestationRequest) (*VerifyAttestationResponse, error)
	VerifyConfidentialSpace(ctx context.Context, request VerifyAttestationRequest) (*VerifyAttestationResponse, error)
}

// Challenge is the response for CreateChallenge. It is used in the
// get challenge part of a remote attestation protocol. The challenge
// will be verified as part of VerifyAttestation.
type Challenge struct {
	// Used as audience for GCP credential tokens.
	Name string
	// Used to generate attestation.
	Nonce     []byte
	ConnID    string
	Val       []byte
	Iat       []byte
	Signature []byte
}

type ContainerSignature struct {
	Payload   []byte
	Signature []byte
}

// VerifyAttestationRequest is passed in on VerifyAttestation. It contains the
// Challenge from CreateChallenge, optional GcpCredentials linked to the
// attestation, the Attestation generated from the TPM, and optional container image signatures associated with the workload.
type VerifyAttestationRequest struct {
	Challenge      *Challenge
	GcpCredentials [][]byte
	// Attestation is for TPM attestation
	Attestation              *attestpb.Attestation
	ContainerImageSignatures []*ContainerSignature
	TokenOptions             *models.TokenOptions
	// TDCCELAttestation is for TDX CCEL RTMR attestation
	TDCCELAttestation *TDCCELAttestation
}

// AttestationEvidence contains either a TPM attestation or a TDX attestation.
type AttestationEvidence struct {
	Attestation       *attestpb.Attestation `json:"attestation,omitempty"`
	TDCCELAttestation *TDCCELAttestation    `json:"tdccel_attestation,omitempty"`
}

type TDCCELAttestation struct {
	CcelAcpiTable     []byte
	CcelData          []byte
	CanonicalEventLog []byte
	TdQuote           []byte
	// still needs following two for GCE info
	AkCert            []byte
	IntermediateCerts [][]byte
}

// VerifyAttestationResponse is the response from a successful
// VerifyAttestation call.
type VerifyAttestationResponse struct {
	ClaimsToken []byte
	PartialErrs []*status.Status
}

// ITAConfig represents the configuration needed to integrate with ITA as a verifier.
type ITAConfig struct {
	ITARegion string
	ITAKey    string
}

// AttestClients contains clients for supported verifier services that can be used to
// get attestation tokens.
type AttestClients struct {
	GCA Client
	ITA Client
}

// HasThirdPartyClient returns true if AttestClients contains an initialzied
// third-party verifier client.
func (ac *AttestClients) HasThirdPartyClient() bool {
	return ac.ITA != nil
}
