// Package grpcclient contains the verifier.Client implementation for a gRPC
// attestation verifier.
package grpcclient

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/google/go-tpm-tools/launcher/verifier"
	servpb "github.com/google/go-tpm-tools/launcher/verifier/grpcclient/proto/attestation_verifier/v0"
	"google.golang.org/grpc"
)

type grpcClient struct {
	pbClient servpb.AttestationVerifierClient
	logger   *log.Logger
}

// NewClient returns a verifier.Client which connects to the prototype service
// via gRPC. Its gRPC definition is at:
// github.com/google/go-tpm-tools/launcher/verifier/grpcclient/proto/attestation_verifier/v0.
func NewClient(conn *grpc.ClientConn, logger *log.Logger) verifier.Client {
	return &grpcClient{
		pbClient: servpb.NewAttestationVerifierClient(conn),
		logger:   logger,
	}
}

// CreateChallenge returns a Challenge. This challenge contains an audience
// used when generating the optional GcpCredentials, a nonce for TPM2_Quote,
// and a service-specific connection ID used when calling Verify.
func (c *grpcClient) CreateChallenge(ctx context.Context) (*verifier.Challenge, error) {
	params, err := c.pbClient.GetParams(ctx, &servpb.GetParamsRequest{})
	c.logger.Println("Calling gRPC attestation verifier GetParams")
	if err != nil {
		return nil, fmt.Errorf("failed GetParams call: %v", err)
	}
	c.logger.Println(params.String())

	return &verifier.Challenge{
		Name:   params.GetAudience(),
		Nonce:  params.GetNonce(),
		ConnID: params.GetConnId(),
	}, nil
}

// VerifyAttestation verifies an attestation generated using the challenge.
// The verifier expects the optional GcpCredentials to have an audience
// with the Challenge.Name and the attestation quote to use the Challenge.Nonce.
// VerifyAttestation also uses the Challenge.connId to reference the original
// connection ID of CreateChallenge.
func (c *grpcClient) VerifyAttestation(ctx context.Context, request verifier.VerifyAttestationRequest) (*verifier.VerifyAttestationResponse, error) {
	if request.Challenge == nil {
		return nil, errors.New("failed VerifyAttestation: VerifyAttestationRequest did not contain Challenge")
	}
	if request.Attestation == nil {
		return nil, errors.New("failed VerifyAttestation: VerifyAttestationRequest did not contain Attestation")
	}
	req := &servpb.VerifyRequest{
		ConnId:            request.Challenge.ConnID,
		Attestation:       request.Attestation,
		PrincipalIdTokens: request.GcpCredentials,
	}
	c.logger.Println("Calling gRPC attestation verifier Verify")
	resp, err := c.pbClient.Verify(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed Verify call: %v", err)
	}
	return &verifier.VerifyAttestationResponse{
		ClaimsToken: resp.GetClaimsToken(),
	}, nil
}
