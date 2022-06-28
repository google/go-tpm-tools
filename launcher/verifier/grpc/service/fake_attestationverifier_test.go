package service

import (
	"context"
	"testing"

	servpb "github.com/google/go-tpm-tools/launcher/verifier/grpc/proto/attestation_verifier/v0"
	pb "github.com/google/go-tpm-tools/proto/attest"
)

func TestGetParamsSuccess(t *testing.T) {
	s := New()
	ctx := context.Background()

	resp, err := s.GetParams(ctx, &servpb.GetParamsRequest{})
	if err != nil {
		t.Errorf("Want no error from GetParams, got %v", err)
	}

	if resp.GetConnId() == "" {
		t.Errorf("Want non-empty connection ID, got %v", resp.GetConnId())
	}

	if len(resp.GetNonce()) == 0 {
		t.Errorf("Want non-empty nonce, got: %v", resp.GetNonce())
	}

	if resp.GetAudience() == "" {
		t.Errorf("Want non-empty audience, got %v", resp.GetAudience())
	}
}

func TestGetParamsNoRepeatedConnIDs(t *testing.T) {
	s := New()
	ctx := context.Background()

	seen := make(map[string]bool)

	for i := 0; i < 100; i++ {
		resp, err := s.GetParams(ctx, &servpb.GetParamsRequest{})
		if err != nil {
			t.Errorf("Want no error from GetParams, got %v", err)
		}

		if seen[resp.GetConnId()] {
			t.Errorf("Found duplicate connection ID: %v:", resp.GetConnId())
		}

		seen[resp.GetConnId()] = true
	}
}

func TestVerifyEmptyConnID(t *testing.T) {
	s := New()
	ctx := context.Background()

	if _, err := s.Verify(ctx, &servpb.VerifyRequest{}); err == nil {
		t.Errorf("Want error after providing no connection ID, got none")
	}
}

func TestVerifyInvalidConnID(t *testing.T) {
	s := New()
	ctx := context.Background()

	if _, err := s.Verify(ctx, &servpb.VerifyRequest{ConnId: "bad"}); err == nil {
		t.Errorf("Want error after providing bad connection ID, got none")
	}
}

func TestVerifyNoAttestation(t *testing.T) {
	s := New()
	ctx := context.Background()

	// Get valid connection ID from a call to GetParams.
	resp, err := s.GetParams(ctx, &servpb.GetParamsRequest{})
	if err != nil {
		t.Errorf("Want no error from GetParams, got %v", err)
	}

	if _, err := s.Verify(ctx, &servpb.VerifyRequest{ConnId: resp.GetConnId()}); err == nil {
		t.Errorf("Want error after providing no attestation, got none")
	}
}

func TestVerifySuccess(t *testing.T) {
	s := New()
	ctx := context.Background()

	// Get valid connection ID from a call to GetParams.
	resp, err := s.GetParams(ctx, &servpb.GetParamsRequest{})
	if err != nil {
		t.Errorf("Want no error from GetParams, got %v", err)
	}

	req := &servpb.VerifyRequest{
		ConnId:      resp.GetConnId(),
		Attestation: &pb.Attestation{EventLog: []byte("I am an event log")},
	}

	verifyResp, err := s.Verify(ctx, req)
	if err != nil {
		t.Errorf("Want no error from Verify, got: %v", err)
	}
	// TODO(b/206146397): Verify attestation, checking nonce.

	// TODO(b/206146397): Check signing key and claims in fake OIDC token response.
	if len(verifyResp.GetClaimsToken()) == 0 {
		t.Errorf("Want non-empty claims token, got: %v", verifyResp.GetClaimsToken())
	}
}
