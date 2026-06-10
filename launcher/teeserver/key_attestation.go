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

// KeyEndorsementAttester defines the interface for obtaining key endorsements.
type KeyEndorsementAttester interface {
	GetKeyEndorsement(ctx context.Context, req *tspb.GetKeyEndorsementRequest, attestOpts agent.AttestAgentOpts) (*attestationpb.VmAttestation, error)
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

func (a *localKEMAttester) GetKeyEndorsement(ctx context.Context, req *tspb.GetKeyEndorsementRequest, attestOpts agent.AttestAgentOpts) (*attestationpb.VmAttestation, error) {
	kemKeyClaims, err := a.keyClaimsProvider.GetKeyClaims(ctx, req.KeyHandle.Handle, keymanager.KeyType_KEY_TYPE_VM_PROTECTION_KEY)
	if err != nil {
		return nil, fmt.Errorf("failed to get KEM key claims")
	}

	kemBytes, err := proto.Marshal(kemKeyClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal KEM key claims: %v", err)
	}

	kemEvidence, err := a.attestAgent.AttestationEvidence(ctx, req.Challenge, kemBytes, attestOpts)
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

func (a *remoteKEMAttester) GetKeyEndorsement(ctx context.Context, req *tspb.GetKeyEndorsementRequest, _ agent.AttestAgentOpts) (*attestationpb.VmAttestation, error) {
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

// localBindingKeyAttester handles attestation requests inside the TEE locally.
type localBindingKeyAttester struct {
	keyClaimsProvider wsd.KeyClaimsProvider
	attestAgent       agent.AttestationAgent
}

func newLocalBindingKeyAttester(keyClaimsProvider wsd.KeyClaimsProvider, attestAgent agent.AttestationAgent) *localBindingKeyAttester {
	return &localBindingKeyAttester{
		keyClaimsProvider: keyClaimsProvider,
		attestAgent:       attestAgent,
	}
}

func (a *localBindingKeyAttester) GetKeyEndorsement(ctx context.Context, req *tspb.GetKeyEndorsementRequest, attestOpts agent.AttestAgentOpts) (*attestationpb.VmAttestation, error) {
	// Querying specifically for the Binding Key type claims
	bindingKeyClaims, err := a.keyClaimsProvider.GetKeyClaims(ctx, req.KeyHandle.Handle, keymanager.KeyType_KEY_TYPE_VM_PROTECTION_BINDING)
	if err != nil {
		return nil, fmt.Errorf("failed to get binding key claims: %v", err)
	}

	bindingBytes, err := proto.Marshal(bindingKeyClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal binding key claims: %v", err)
	}

	bindingEvidence, err := a.attestAgent.AttestationEvidence(ctx, req.Challenge, bindingBytes, attestOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to collect attestation evidence with binding key claims: %v", err)
	}
	return bindingEvidence, nil
}

func (a *localBindingKeyAttester) Close() error {
	return nil
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
