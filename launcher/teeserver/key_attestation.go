package teeserver

import (
	"context"
	"fmt"
	"time"

	attestationpb "github.com/GoogleCloudPlatform/confidential-space/server/proto/gen/attestation"

	pb "github.com/GoogleCloudPlatform/key-protection-module/keymanager/attestation_service/proto/gen"

	kpmkeymanager "github.com/GoogleCloudPlatform/key-protection-module/km_common/proto"
	"github.com/google/go-tpm-tools/agent"

	tspb "github.com/google/go-tpm-tools/launcher/teeserver/proto/gen/teeserver"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

const defaultTimeout = 30 * time.Second

// KeyEndorsementAttester defines the interface for obtaining key endorsements.
type KeyEndorsementAttester interface {
	GetKeyEndorsement(ctx context.Context, req *tspb.GetKeyEndorsementRequest, attestOpts agent.AttestAgentOpts) (*attestationpb.VmAttestation, error)
	Close() error
}

type remoteKEMAttester struct {
	client pb.AttestationServiceClient
	conn   *grpc.ClientConn
}

func newRemoteKEMAttester(conn *grpc.ClientConn) *remoteKEMAttester {
	return &remoteKEMAttester{
		client: pb.NewAttestationServiceClient(conn),
		conn:   conn,
	}
}

func (a *remoteKEMAttester) Close() error {
	return a.conn.Close()
}

func (a *remoteKEMAttester) GetKeyEndorsement(ctx context.Context, req *tspb.GetKeyEndorsementRequest, _ agent.AttestAgentOpts) (*attestationpb.VmAttestation, error) {
	if req.KeyHandle == nil {
		return nil, fmt.Errorf("key handle is nil")
	}
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	kemReq := &pb.GetKeyEndorsementRequest{
		Challenge: req.Challenge,
		KeyHandle: &kpmkeymanager.KeyHandle{
			Handle: req.KeyHandle.Handle,
		},
		RequestAcpiData: req.RequestAcpiData,
	}
	resp, err := a.client.GetKeyEndorsement(ctx, kemReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get remote key endorsement: %v", err)
	}

	if resp == nil || resp.GetKeyAttestation() == nil {
		return nil, fmt.Errorf("remote key endorsement response is malformed")
	}
	return resp.GetKeyAttestation().GetAttestation(), nil
}

// bcBindingKeyAttester connects to a remote server over a Unix domain socket.
type bcBindingKeyAttester struct {
	conn        *grpc.ClientConn
	client      kpmkeymanager.KeyClaimsServiceClient
	attestAgent agent.AttestationAgent
}

// newBCBindingKeyAttester establishes a gRPC client connection using a Unix Domain Socket (UDS).
func newBCBindingKeyAttester(conn *grpc.ClientConn, attestAgent agent.AttestationAgent) *bcBindingKeyAttester {
	return &bcBindingKeyAttester{
		client:      kpmkeymanager.NewKeyClaimsServiceClient(conn),
		conn:        conn,
		attestAgent: attestAgent,
	}
}

func (a *bcBindingKeyAttester) GetKeyEndorsement(ctx context.Context, req *tspb.GetKeyEndorsementRequest, attestOpts agent.AttestAgentOpts) (*attestationpb.VmAttestation, error) {
	if req.KeyHandle == nil {
		return nil, fmt.Errorf("key handle is nil")
	}
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	bindingReq := &kpmkeymanager.GetKeyClaimsRequest{
		KeyHandle: &kpmkeymanager.KeyHandle{
			Handle: req.KeyHandle.Handle,
		},
		KeyType: kpmkeymanager.KeyType_KEY_TYPE_VM_PROTECTION_BINDING,
	}

	resp, err := a.client.GetKeyClaims(ctx, bindingReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get remote binding key endorsement: %v", err)
	}

	if resp == nil || resp.GetClaims() == nil || resp.GetVmBindingClaims() == nil {
		return nil, fmt.Errorf("remote key endorsement response is malformed")
	}

	bindingBytes, err := proto.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal binding key claims: %v", err)
	}

	bindingEvidence, err := a.attestAgent.AttestationEvidence(ctx, req.Challenge, bindingBytes, attestOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to collect attestation evidence with binding key claims: %v", err)
	}
	return bindingEvidence, nil
}

func (a *bcBindingKeyAttester) Close() error {
	return a.conn.Close()
}
