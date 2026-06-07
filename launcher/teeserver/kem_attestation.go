package teeserver

import (
	"context"
	"fmt"
	"time"

	// Bootstrap environment flags to prevent duplicate proto registration panics.
	_ "github.com/google/go-tpm-tools/launcher/teeserver/envinit"

	attestationpb "github.com/GoogleCloudPlatform/confidential-space/server/proto/gen/attestation"

	pb "github.com/GoogleCloudPlatform/key-protection-module/keymanager/attestation_service/proto/gen"

	kpmkeymanager "github.com/GoogleCloudPlatform/key-protection-module/km_common/proto"
	"github.com/google/go-tpm-tools/agent"

	keymanager "github.com/google/go-tpm-tools/keymanager/km_common/proto"

	wsd "github.com/google/go-tpm-tools/keymanager/workload_service"

	tspb "github.com/google/go-tpm-tools/launcher/teeserver/proto/gen/teeserver"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

const defaultTimeout = 30 * time.Second

// KEMAttester defines the interface for obtaining key endorsements.
type KEMAttester interface {
	GetKeyEndorsement(ctx context.Context, req *tspb.GetKeyEndorsementRequest) (*attestationpb.VmAttestation, error)
	Close() error
}

type localKEMAttester struct {
	keyClaimsProvider wsd.KeyClaimsProvider
	attestAgent       agent.AttestationAgent
}

func newLocalKEMAttester(keyClaimsProvider wsd.KeyClaimsProvider, attestAgent agent.AttestationAgent) *localKEMAttester {
	return &localKEMAttester{
		keyClaimsProvider: keyClaimsProvider,
		attestAgent:       attestAgent,
	}
}

func (a *localKEMAttester) Close() error {
	return nil
}

func (a *localKEMAttester) GetKeyEndorsement(ctx context.Context, req *tspb.GetKeyEndorsementRequest) (*attestationpb.VmAttestation, error) {
	kemKeyClaims, err := a.keyClaimsProvider.GetKeyClaims(ctx, req.KeyHandle.Handle, keymanager.KeyType_KEY_TYPE_VM_PROTECTION_KEY)
	if err != nil {
		return nil, fmt.Errorf("failed to get KEM key claims")
	}

	kemBytes, err := proto.Marshal(kemKeyClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal KEM key claims: %v", err)
	}

	kemEvidence, err := a.attestAgent.AttestationEvidence(ctx, req.Challenge, kemBytes, agent.AttestAgentOpts{})
	if err != nil {
		return nil, fmt.Errorf("failed to collect attestation evidence with kem key claims")
	}
	return kemEvidence, nil
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

func (a *remoteKEMAttester) GetKeyEndorsement(ctx context.Context, req *tspb.GetKeyEndorsementRequest) (*attestationpb.VmAttestation, error) {
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	kemReq := &pb.GetKeyEndorsementRequest{
		Challenge: req.Challenge,
		KeyHandle: &kpmkeymanager.KeyHandle{
			Handle: req.KeyHandle.Handle,
		},
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
