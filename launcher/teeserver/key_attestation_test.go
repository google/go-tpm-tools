package teeserver

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	// Bootstrap environment flags to prevent duplicate proto registration panics.

	_ "github.com/google/go-tpm-tools/launcher/teeserver/envinit"

	attestationpb "github.com/GoogleCloudPlatform/confidential-space/server/proto/gen/attestation"

	pb "github.com/GoogleCloudPlatform/key-protection-module/keymanager/attestation_service/proto/gen"
	"github.com/google/go-cmp/cmp"

	keymanager "github.com/google/go-tpm-tools/keymanager/km_common/proto"

	tspb "github.com/google/go-tpm-tools/launcher/teeserver/proto/gen/teeserver"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestLocalKEMAttester_GetKeyEndorsement(t *testing.T) {
	testClaims := &keymanager.KeyClaims{
		Claims: &keymanager.KeyClaims_VmKeyClaims{
			VmKeyClaims: &keymanager.KeyClaims_VmProtectionKeyClaims{
				ExpirationTime: 123456,
			},
		},
	}
	testEvidence := &attestationpb.VmAttestation{
		Label: []byte("test-evidence"),
	}
	testChallenge := []byte("test-challenge")
	testHandle := "test-handle"

	tests := []struct {
		name                 string
		claimsProviderErr    error
		claimsProviderResp   map[keymanager.KeyType]*keymanager.KeyClaims
		attestationAgentErr  error
		attestationAgentResp *attestationpb.VmAttestation
		wantErrSubstr        string
	}{
		{
			name: "success",
			claimsProviderResp: map[keymanager.KeyType]*keymanager.KeyClaims{
				keymanager.KeyType_KEY_TYPE_VM_PROTECTION_KEY: testClaims,
			},
			attestationAgentResp: testEvidence,
		},
		{
			name:              "claims provider error",
			claimsProviderErr: errors.New("failed to get claims"),
			wantErrSubstr:     "failed to get KEM key claims",
		},
		{
			name: "attestation agent error",
			claimsProviderResp: map[keymanager.KeyType]*keymanager.KeyClaims{
				keymanager.KeyType_KEY_TYPE_VM_PROTECTION_KEY: testClaims,
			},
			attestationAgentErr: errors.New("attestation agent error"),
			wantErrSubstr:       "failed to collect attestation evidence with kem key claims",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockClaims := &mockClaimsProvider{
				claims: tc.claimsProviderResp,
				err:    tc.claimsProviderErr,
			}
			mockAgent := fakeAttestationAgent{
				attestationEvidenceFunc: func(_ context.Context, _ []byte, extraData []byte) (*attestationpb.VmAttestation, error) {
					if tc.attestationAgentErr != nil {
						return nil, tc.attestationAgentErr
					}
					// Verify extraData contains the marshaled key claims
					marshaledClaims, _ := proto.Marshal(testClaims)
					if tc.attestationAgentResp != nil {
						if diff := cmp.Diff(marshaledClaims, extraData); diff != "" {
							t.Errorf("AttestationEvidence extraData mismatch (-want +got):\n%s", diff)
						}
					}
					return tc.attestationAgentResp, nil
				},
			}

			attester := newLocalKEMAttester(mockClaims, mockAgent)
			req := &tspb.GetKeyEndorsementRequest{
				Challenge: testChallenge,
				KeyHandle: &keymanager.KeyHandle{
					Handle: testHandle,
				},
			}

			got, err := attester.GetKeyEndorsement(context.Background(), req)
			if tc.wantErrSubstr != "" {
				if err == nil {
					t.Fatalf("GetKeyEndorsement() returned no error, want error containing %q", tc.wantErrSubstr)
				}
				if !strings.Contains(err.Error(), tc.wantErrSubstr) {
					t.Errorf("GetKeyEndorsement() error = %v, want error containing %q", err, tc.wantErrSubstr)
				}
				return
			}

			if err != nil {
				t.Fatalf("GetKeyEndorsement() returned unexpected error: %v", err)
			}

			if diff := cmp.Diff(tc.attestationAgentResp, got, protocmp.Transform()); diff != "" {
				t.Errorf("GetKeyEndorsement() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

type fakeAttestationServiceServer struct {
	pb.UnimplementedAttestationServiceServer
	GetKeyEndorsementFunc func(context.Context, *pb.GetKeyEndorsementRequest) (*pb.GetKeyEndorsementResponse, error)
}

func (s *fakeAttestationServiceServer) GetKeyEndorsement(ctx context.Context, req *pb.GetKeyEndorsementRequest) (*pb.GetKeyEndorsementResponse, error) {
	if s.GetKeyEndorsementFunc != nil {
		return s.GetKeyEndorsementFunc(ctx, req)
	}
	return nil, errors.New("unimplemented GetKeyEndorsementFunc")
}

func TestRemoteKEMAttester_GetKeyEndorsement(t *testing.T) {
	testEvidence := &attestationpb.VmAttestation{
		Label: []byte("test-evidence"),
	}
	testChallenge := []byte("test-challenge")
	testHandle := "test-handle"

	tests := []struct {
		name          string
		grpcErr       error
		grpcResp      *pb.GetKeyEndorsementResponse
		wantErrSubstr string
	}{
		{
			name: "success",
			grpcResp: &pb.GetKeyEndorsementResponse{
				KeyAttestation: &attestationpb.KeyAttestation{
					Attestation: testEvidence,
				},
			},
		},
		{
			name:          "gRPC error",
			grpcErr:       errors.New("gRPC connection failed"),
			wantErrSubstr: "failed to get remote key endorsement",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Set up bufconn listener
			lis := bufconn.Listen(1024 * 1024)
			s := grpc.NewServer()
			fakeServer := &fakeAttestationServiceServer{
				GetKeyEndorsementFunc: func(_ context.Context, req *pb.GetKeyEndorsementRequest) (*pb.GetKeyEndorsementResponse, error) {
					if tc.grpcErr != nil {
						return nil, tc.grpcErr
					}
					// Verify requests parameters are passed correctly
					if diff := cmp.Diff(testChallenge, req.Challenge); diff != "" {
						t.Errorf("gRPC request Challenge mismatch (-want +got):\n%s", diff)
					}
					if req.KeyHandle == nil || req.KeyHandle.Handle != testHandle {
						t.Errorf("gRPC request KeyHandle mismatch: got %v, want handle %q", req.KeyHandle, testHandle)
					}
					return tc.grpcResp, nil
				},
			}
			pb.RegisterAttestationServiceServer(s, fakeServer)

			go func() {
				if err := s.Serve(lis); err != nil && err != grpc.ErrServerStopped {
					t.Errorf("Server exited with error: %v", err)
				}
			}()
			defer s.Stop()

			// Set up gRPC client connection
			ctx := context.Background()
			conn, err := grpc.NewClient("passthrough:///bufconn",
				grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
					return lis.Dial()
				}),
				grpc.WithTransportCredentials(insecure.NewCredentials()),
			)
			if err != nil {
				t.Fatalf("Failed to dial bufconn: %v", err)
			}
			defer conn.Close()

			attester := newRemoteKEMAttester(conn)
			req := &tspb.GetKeyEndorsementRequest{
				Challenge: testChallenge,
				KeyHandle: &keymanager.KeyHandle{
					Handle: testHandle,
				},
			}

			got, err := attester.GetKeyEndorsement(ctx, req)
			if tc.wantErrSubstr != "" {
				if err == nil {
					t.Fatalf("GetKeyEndorsement() returned no error, want error containing %q", tc.wantErrSubstr)
				}
				if !strings.Contains(err.Error(), tc.wantErrSubstr) {
					t.Errorf("GetKeyEndorsement() error = %v, want error containing %q", err, tc.wantErrSubstr)
				}
				return
			}

			if err != nil {
				t.Fatalf("GetKeyEndorsement() returned unexpected error: %v", err)
			}

			if diff := cmp.Diff(testEvidence, got, protocmp.Transform()); diff != "" {
				t.Errorf("GetKeyEndorsement() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
