package verifier

import (
	"context"
	"errors"
	"fmt"
	"log"

	servpb "github.com/google/go-tpm-tools/launcher/proto/attestation_verifier/v0"
)

type GRPCClient struct {
	pbClient servpb.AttestationVerifierClient
	logger   *log.Logger
}

func NewGRPCClient(pbClient servpb.AttestationVerifierClient, logger *log.Logger) *GRPCClient {
	return &GRPCClient{
		pbClient: pbClient,
		logger:   logger,
	}
}

func (c *GRPCClient) CreateChallenge(ctx context.Context) (*Challenge, error) {
	params, err := c.pbClient.GetParams(ctx, &servpb.GetParamsRequest{})
	c.logger.Println("Calling gRPC attestation verifier GetParams")
	if err != nil {
		return nil, fmt.Errorf("failed GetParams call: %v", err)
	}
	c.logger.Println(params.String())

	return &Challenge{
		name:   params.GetAudience(),
		nonce:  params.GetNonce(),
		connId: params.GetConnId(),
	}, nil
}

func (c *GRPCClient) VerifyAttestation(ctx context.Context, request VerifyAttestationRequest) (*VerifyAttestationResponse, error) {
	if request.Challenge == nil {
		return nil, errors.New("failed VerifyAttestation: VerifyAttestationRequest did not contain Challenge")
	}
	if request.Attestation == nil {
		return nil, errors.New("failed VerifyAttestation: VerifyAttestationRequest did not contain Attestation")
	}
	req := &servpb.VerifyRequest{ConnId: request.Challenge.connId, Attestation: request.Attestation, PrincipalIdTokens: request.GcpCredentials}
	c.logger.Println("Calling gRPC attestation verifier Verify")
	resp, err := c.pbClient.Verify(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed Verify call: %v", err)
	}
	return &VerifyAttestationResponse{
		claimsToken: resp.GetClaimsToken(),
	}, nil
}
