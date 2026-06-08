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
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

const defaultTimeout = 30 * time.Second

// KeyAttester defines the interface for obtaining key endorsements.
type KeyAttester interface {
	GetKeyEndorsement(ctx context.Context, req *tspb.GetKeyEndorsementRequest) (*attestationpb.VmAttestation, error)
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
	conn *grpc.ClientConn
}

func newRemoteKEMAttester(conn *grpc.ClientConn) *remoteKEMAttester {
	return &remoteKEMAttester{
		conn: conn,
	}
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
	client := pb.NewAttestationServiceClient(a.conn)
	resp, err := client.GetKeyEndorsement(ctx, kemReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get remote key endorsement: %v", err)
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

func (a *localBindingKeyAttester) GetKeyEndorsement(ctx context.Context, req *tspb.GetKeyEndorsementRequest) (*attestationpb.VmAttestation, error) {
	// Querying specifically for the Binding Key type claims
	bindingKeyClaims, err := a.keyClaimsProvider.GetKeyClaims(ctx, req.KeyHandle.Handle, keymanager.KeyType_KEY_TYPE_VM_PROTECTION_BINDING)
	if err != nil {
		return nil, fmt.Errorf("failed to get binding key claims: %v", err)
	}

	bindingBytes, err := proto.Marshal(bindingKeyClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal binding key claims: %v", err)
	}

	bindingEvidence, err := a.attestAgent.AttestationEvidence(ctx, req.Challenge, bindingBytes, agent.AttestAgentOpts{})
	if err != nil {
		return nil, fmt.Errorf("failed to collect attestation evidence with binding key claims: %v", err)
	}
	return bindingEvidence, nil
}

// remoteBindingKeyAttester connects to a remote server over a Unix domain socket.
type remoteBindingKeyAttester struct {
	conn *grpc.ClientConn
}

// newRemoteBindingKeyAttester establishes a gRPC client connection using a Unix Domain Socket (UDS).
func newRemoteBindingKeyAttester(socketPath string) (*remoteBindingKeyAttester, error) {
	// gRPC natively supports the unix:// scheme for resolving UDS paths
	conn, err := grpc.Dial(
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to dial remote server via unix socket %s: %v", socketPath, err)
	}

	return &remoteBindingKeyAttester{
		conn: conn,
	}, nil
}

func (a *remoteBindingKeyAttester) GetKeyEndorsement(ctx context.Context, req *tspb.GetKeyEndorsementRequest) (*attestationpb.VmAttestation, error) {
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	bindingReq := &kpmkeymanager.GetKeyClaimsRequest{
		KeyHandle: &kpmkeymanager.KeyHandle{
			Handle: req.KeyHandle.Handle,
		},
		KeyType: kpmkeymanager.KeyType_KEY_TYPE_VM_PROTECTION_BINDING,
	}

	client := kpmkeymanager.NewKeyClaims
	resp, err := client.GetKeyClaims(ctx, bindingReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get remote binding key endorsement: %v", err)
	}

	return resp.GetKeyAttestation().GetAttestation(), nil
}
