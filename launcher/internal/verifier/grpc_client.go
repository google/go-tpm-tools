package verifier

import (
	"context"
	"errors"
	"fmt"
	"log"

	servpb "github.com/google/go-tpm-tools/launcher/internal/verifier/proto/attestation_verifier/v0"
)

// GRPCClient makes calls to a gRPC attestation verifier.
// Its gRPC definition is at github.com/google/go-tpm-tools/launcher/internal/verifier/proto/attestation_verifier/v0.
type GRPCClient struct {
	pbClient servpb.AttestationVerifierClient
	logger   *log.Logger
}

// NewGRPCClient returns a GRPCClient implementing verifier.Client.
func NewGRPCClient(pbClient servpb.AttestationVerifierClient, logger *log.Logger) *GRPCClient {
	return &GRPCClient{
		pbClient: pbClient,
		logger:   logger,
	}
}

// CreateChallenge returns a Challenge. This challenge contains an audience
// used when generating the optional GcpCredentials, a nonce for TPM2_Quote,
// and a service-specific connection ID used when calling Verify.
func (c *GRPCClient) CreateChallenge(ctx context.Context) (*Challenge, error) {
	params, err := c.pbClient.GetParams(ctx, &servpb.GetParamsRequest{})
	c.logger.Println("Calling gRPC attestation verifier GetParams")
	if err != nil {
		return nil, fmt.Errorf("failed GetParams call: %v", err)
	}
	c.logger.Println(params.String())

	return &Challenge{
		Name:   params.GetAudience(),
		Nonce:  params.GetNonce(),
		connID: params.GetConnId(),
	}, nil
}

// VerifyAttestation verifies an attestation generated using the challenge.
// The verifier expects the optional GcpCredentials to have an audience
// with the Challenge.Name and the attestation quote to use the Challenge.Nonce.
// VerifyAttestation also uses the Challenge.connId to reference the original
// connection ID of CreateChallenge.
func (c *GRPCClient) VerifyAttestation(ctx context.Context, request VerifyAttestationRequest) (*VerifyAttestationResponse, error) {
	if request.Challenge == nil {
		return nil, errors.New("failed VerifyAttestation: VerifyAttestationRequest did not contain Challenge")
	}
	if request.Attestation == nil {
		return nil, errors.New("failed VerifyAttestation: VerifyAttestationRequest did not contain Attestation")
	}
	req := &servpb.VerifyRequest{
		ConnId:            request.Challenge.connID,
		Attestation:       request.Attestation,
		PrincipalIdTokens: request.GcpCredentials,
	}
	c.logger.Println("Calling gRPC attestation verifier Verify")
	resp, err := c.pbClient.Verify(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed Verify call: %v", err)
	}
	return &VerifyAttestationResponse{
		ClaimsToken: resp.GetClaimsToken(),
	}, nil
}
