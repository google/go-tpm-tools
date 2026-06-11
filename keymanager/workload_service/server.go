// Package workloadservice implements the Key Orchestration Layer (KOL) for the
// Workload Service Daemon (WSD). It provides an HTTP server on a unix socket
// exposing key management endpoints.
package workloadservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"buf.build/go/protovalidate"
	kpscc "github.com/google/go-tpm-tools/keymanager/key_protection_service/key_custody_core"
	keymanager "github.com/google/go-tpm-tools/keymanager/km_common/proto"
	wskcc "github.com/google/go-tpm-tools/keymanager/workload_service/key_custody_core"
	api "github.com/google/go-tpm-tools/keymanager/workload_service/proto"
	"github.com/google/uuid"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

// WorkloadService defines the interface for generating and managing binding keypairs.
// These keypairs are used by workloads to securely bind shared secrets to their identity.
type WorkloadService interface {
	// GenerateBindingKeypair generates a new binding keypair for a workload.
	// This keypair ensures that only the workload possessing the private key
	// can open (decrypt) sealed secrets intended for it.
	//
	// Parameters:
	//   - algo: The HPKE algorithm suite to use for the binding keypair.
	//   - lifespanSecs: The duration (in seconds) for which the generated keypair remains valid.
	//
	// Returns:
	//   - uuid.UUID: A unique identifier representing the stored binding keypair.
	//   - []byte: The public binding key bytes to be shared with the Key Protection Service.
	//   - error: An error if generation or storage fails.
	GenerateBindingKeypair(algo *keymanager.HpkeAlgorithm, lifespanSecs uint64) (uuid.UUID, []byte, error)

	// DestroyBindingKey removes the specified binding keypair from the active key registry.
	// It ensures that the keypair can no longer be used to decrypt (open) sealed secrets.
	//
	// Parameters:
	//   - bindingUUID: The unique identifier of the stored binding keypair to destroy.
	//
	// Returns:
	//   - error: An error if the key is not found or deletion fails.
	DestroyBindingKey(bindingUUID uuid.UUID) error

	// GetBindingKey retrieves metadata and public keys associated with a stored binding keypair.
	//
	// Parameters:
	//   - id: The unique identifier of the stored binding keypair.
	//
	// Returns:
	//   - []byte: The public binding key bytes.
	//   - *keymanager.HpkeAlgorithm: The HPKE algorithm suite of the binding key.
	//   - error: An error if the key is not found or has expired.
	GetBindingKey(id uuid.UUID) ([]byte, *keymanager.HpkeAlgorithm, error)

	// Open decrypts a sealed ciphertext using the specified binding private key.
	// It is used by the workload to access shared secrets that have been resealed
	// for its specific binding key.
	//
	// Parameters:
	//   - bindingUUID: The unique identifier of the stored binding keypair.
	//   - enc: The encapsulated key for the resealed shared secret (seal_enc).
	//   - ciphertext: The authenticated ciphertext of the resealed shared secret (sealed_ct).
	//   - aad: Additional Authenticated Data used during the sealing process.
	//
	// Returns:
	//   - []byte: The original plaintext (the shared secret).
	//   - error: An error if the binding key is not found, expired, or decryption fails.
	Open(bindingUUID uuid.UUID, enc, ciphertext, aad []byte) ([]byte, error)
}
type keyProtectionService struct{}

// KeyProtectionService defines the interface for generating KEM keypairs.
type KeyProtectionService interface {
	GenerateKEMKeypair(algo *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error)
	EnumerateKEMKeys(limit, offset int) ([]kpscc.KEMKeyInfo, bool, error)
	DestroyKEMKey(kemUUID uuid.UUID) error
	GetKEMKey(id uuid.UUID) (kemPubKey []byte, bindingPubKey []byte, algo *keymanager.HpkeAlgorithm, deleteAfter uint64, err error)
	DecapAndSeal(kemUUID uuid.UUID, encapsulatedKey, aad []byte) (sealEnc []byte, sealedCT []byte, err error)
}

// workloadService implements WorkloadService by delegating to the WSD KCC FFI.
type workloadService struct{}

// GenerateBindingKeypair generates a new binding keypair for the workload by
// delegating to the underlying WorkloadService backend (WSD KCC FFI).
func (r *workloadService) GenerateBindingKeypair(algo *keymanager.HpkeAlgorithm, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	return wskcc.GenerateBindingKeypair(algo, lifespanSecs)
}

// DestroyBindingKey removes the specified binding keypair from the active key registry
// by delegating to the underlying WorkloadService backend (WSD KCC FFI).
func (r *workloadService) DestroyBindingKey(bindingUUID uuid.UUID) error {
	return wskcc.DestroyBindingKey(bindingUUID)
}

// Open decrypts a sealed ciphertext securely using the specified binding private key
// by delegating to the underlying WorkloadService backend (WSD KCC FFI).
func (r *workloadService) Open(bindingUUID uuid.UUID, enc, ciphertext, aad []byte) ([]byte, error) {
	return wskcc.Open(bindingUUID, enc, ciphertext, aad)
}

// GetBindingKey retrieves the public binding key and HPKE algorithm of a stored
// binding keypair by delegating to the underlying WorkloadService backend (WSD KCC FFI).
func (r *workloadService) GetBindingKey(id uuid.UUID) ([]byte, *keymanager.HpkeAlgorithm, error) {
	return wskcc.GetBindingKey(id)
}

func (r *keyProtectionService) GenerateKEMKeypair(algo *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	return kpscc.GenerateKEMKeypair(algo, bindingPubKey, lifespanSecs)
}

func (r *keyProtectionService) EnumerateKEMKeys(limit, offset int) ([]kpscc.KEMKeyInfo, bool, error) {
	return kpscc.EnumerateKEMKeys(limit, offset)
}

func (r *keyProtectionService) DestroyKEMKey(kemUUID uuid.UUID) error {
	return kpscc.DestroyKEMKey(kemUUID)
}

func (r *keyProtectionService) DecapAndSeal(kemUUID uuid.UUID, encapsulatedKey, aad []byte) (sealEnc []byte, sealedCT []byte, err error) {
	return kpscc.DecapAndSeal(kemUUID, encapsulatedKey, aad)
}

func (r *keyProtectionService) GetKEMKey(id uuid.UUID) ([]byte, []byte, *keymanager.HpkeAlgorithm, uint64, error) {
	return kpscc.GetKEMKey(id)
}

type remoteKeyProtectionService struct{}

func (r *remoteKeyProtectionService) GenerateKEMKeypair(_ *keymanager.HpkeAlgorithm, _ []byte, _ uint64) (uuid.UUID, []byte, error) {
	return uuid.Nil, nil, nil
}

func (r *remoteKeyProtectionService) EnumerateKEMKeys(_, _ int) ([]kpscc.KEMKeyInfo, bool, error) {
	return nil, false, nil
}

func (r *remoteKeyProtectionService) DestroyKEMKey(_ uuid.UUID) error {
	return nil
}

func (r *remoteKeyProtectionService) DecapAndSeal(_ uuid.UUID, _, _ []byte) ([]byte, []byte, error) {
	return nil, nil, nil
}

func (r *remoteKeyProtectionService) GetKEMKey(_ uuid.UUID) ([]byte, []byte, *keymanager.HpkeAlgorithm, uint64, error) {
	return nil, nil, nil, 0, nil
}

// KeyClaimsProvider defines the interface for retrieving key claims.
// This abstraction allows the underlying implementation to be a local channel
// or a remote RPC call in future.
type KeyClaimsProvider interface {
	GetKeyClaims(ctx context.Context, keyHandle string, keyType keymanager.KeyType) (*keymanager.KeyClaims, error)
}

// ClaimsCall acts as the internal "envelope" for the channel.
type ClaimsCall struct {
	Request  *keymanager.GetKeyClaimsRequest
	RespChan chan *ClaimsResult
}

// ClaimsResult wraps the protobuf response with an error.
type ClaimsResult struct {
	Reply *keymanager.KeyClaims
	Err   error
}

// Server is the WSD HTTP server.
type Server struct {
	api.UnimplementedWorkloadServiceServer

	keyProtectionService KeyProtectionService
	workloadService      WorkloadService
	mu                   sync.RWMutex
	kemToBindingMap      map[uuid.UUID]uuid.UUID

	claimsChan chan *ClaimsCall

	httpServer *http.Server
	listener   net.Listener
	grpcServer *grpc.Server
	// todo: add logging mechanism here
}

var (
	// ClaimsResponseTimeout is the maximum time to wait for the caller to receive
	// the result of a GetKeyClaims request before timing out.
	ClaimsResponseTimeout = 5 * time.Second
	// ClaimsRequestTimeout is the maximum time to wait for enqueuing the request to
	// claims channel for getting the key claims.
	ClaimsRequestTimeout = 5 * time.Second
)

// New creates a new WSD Server listening on the given unix socket path.
func New(_ context.Context, socketPath string, mode keymanager.KeyProtectionMechanism) (*Server, error) {
	var kps KeyProtectionService
	switch mode {
	case keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM_EMULATED:
		kps = &keyProtectionService{}
	case keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM:
		kps = &remoteKeyProtectionService{}
	case keymanager.KeyProtectionMechanism_KEY_PROTECTION_MECHANISM_UNSPECIFIED:
		return nil, fmt.Errorf("key protection mechanism is unspecified")
	default:
		return nil, fmt.Errorf("unknown key protection mechanism provided: %v", mode)
	}
	return NewServer(kps, &workloadService{}, socketPath)
}

func handleRoutingError(ctx context.Context, mux *runtime.ServeMux, marshaler runtime.Marshaler, w http.ResponseWriter, r *http.Request, httpStatus int) {
	if httpStatus != http.StatusMethodNotAllowed {
		runtime.DefaultRoutingErrorHandler(ctx, mux, marshaler, w, r, httpStatus)
		return
	}

	// Use HTTPStatusError to customize the DefaultHTTPErrorHandler status code
	err := &runtime.HTTPStatusError{
		HTTPStatus: httpStatus,
		Err:        status.Error(codes.Unimplemented, http.StatusText(httpStatus)),
	}

	runtime.DefaultHTTPErrorHandler(ctx, mux, marshaler, w, r, err)
}

func customHTTPErrorHandler(_ context.Context, _ *runtime.ServeMux, _ runtime.Marshaler, w http.ResponseWriter, _ *http.Request, err error) {
	st := status.Convert(err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(runtime.HTTPStatusFromCode(st.Code()))
	json.NewEncoder(w).Encode(map[string]string{"error": st.Message()})
}

func customResponseModifier(_ context.Context, w http.ResponseWriter, resp proto.Message) error {
	// If the endpoint returned a DestroyResponse, rewrite the status code to 204 No Content
	if _, ok := resp.(*api.DestroyResponse); ok {
		w.WriteHeader(http.StatusNoContent)
	}
	return nil
}

// NewServer creates a new WSD server with the given dependencies.
func NewServer(keyProtectionService KeyProtectionService, workloadService WorkloadService, socketPath string) (*Server, error) {
	s := &Server{
		keyProtectionService: keyProtectionService,
		workloadService:      workloadService,
		kemToBindingMap:      make(map[uuid.UUID]uuid.UUID),
		mu:                   sync.RWMutex{},
		claimsChan:           make(chan *ClaimsCall, 4),
	}
	if socketPath == "" || !filepath.IsAbs(socketPath) {
		return nil, fmt.Errorf("socket path must not be empty")
	}
	restSocketPath := socketPath
	grpcSocketPath := strings.TrimSuffix(socketPath, filepath.Ext(socketPath)) + "-grpc.sock"

	grpcServer, err := initGRPCServer(s, grpcSocketPath)
	if err != nil {
		return nil, err
	}

	httpServer, listener, err := initRESTGatewayProxy(restSocketPath, grpcSocketPath)
	if err != nil {
		grpcServer.GracefulStop()
		return nil, err
	}

	s.grpcServer = grpcServer
	s.httpServer = httpServer
	s.listener = listener

	go s.processClaims()

	return s, nil
}

func initGRPCServer(s *Server, grpcSocketPath string) (*grpc.Server, error) {
	_ = os.Remove(grpcSocketPath)
	grpcListener, err := net.Listen("unix", grpcSocketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on gRPC socket %s: %w", grpcSocketPath, err)
	}

	grpcServer := grpc.NewServer()
	api.RegisterWorkloadServiceServer(grpcServer, s)

	go func() {
		if err := grpcServer.Serve(grpcListener); err != nil {
			log.Printf("native gRPC server stopped: %v", err)
		}
	}()

	return grpcServer, nil
}

func initRESTGatewayProxy(restSocketPath, grpcSocketPath string) (*http.Server, net.Listener, error) {
	conn, err := grpc.NewClient(
		"unix:"+grpcSocketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial internal native gRPC server: %w", err)
	}

	mux := runtime.NewServeMux(
		// Override successful empty metadata responses (e.g. DestroyResponse) to return HTTP 204 No Content
		runtime.WithForwardResponseOption(customResponseModifier),
		// Intercept gRPC status errors and serialize them back into the legacy {"error": "<message>"} JSON layout
		runtime.WithErrorHandler(customHTTPErrorHandler),
		// Preserve original snake_case protobuf field casing and enforce inclusion of empty structures unconditionally
		runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.JSONPb{
			MarshalOptions: protojson.MarshalOptions{
				UseProtoNames:   true,
				EmitUnpopulated: true,
			},
		}),
		// Handle unmapped HTTP/REST routing path and method mismatches securely
		runtime.WithRoutingErrorHandler(handleRoutingError),
	)

	if err := api.RegisterWorkloadServiceHandler(context.Background(), mux, conn); err != nil {
		return nil, nil, fmt.Errorf("failed to register proxy handler: %w", err)
	}

	_ = os.Remove(restSocketPath)
	restListener, err := net.Listen("unix", restSocketPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to listen on REST unix socket %s: %w", restSocketPath, err)
	}

	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Content-Type", "application/json")
			mux.ServeHTTP(w, r)
		}),
	}

	return httpServer, restListener, nil
}

// Serve starts the HTTP server listening on the given unix socket path.
func (s *Server) Serve() error {
	return s.httpServer.Serve(s.listener)
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}
	if s.claimsChan != nil {
		close(s.claimsChan)
	}
	return s.httpServer.Shutdown(ctx)
}

// Handler returns the HTTP handler for testing purposes.
func (s *Server) Handler() http.Handler {
	return s.httpServer.Handler
}

// LookupBindingUUID returns the binding UUID associated with the given KEM UUID.
func (s *Server) LookupBindingUUID(kemUUID uuid.UUID) (uuid.UUID, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.kemToBindingMap[kemUUID]
	return id, ok
}

func decapsAADContext(kemUUID uuid.UUID, algorithm keymanager.KemAlgorithm) []byte {
	// Bind the KPS->WSD transport ciphertext to this decapsulation context.
	// Note: The AAD context string retains `decaps` as it is part of the internal binding protocol
	// and changing it might affect backward compatibility if keys were already persisted (though lifespan is short).
	// For API alignment, we only change the external endpoint and JSON.
	return []byte(fmt.Sprintf("wsd:keys:decaps:v1:%d:%s", algorithm, kemUUID))
}

// Decaps handles the decapsulation of incoming HPKE ciphertext payloads.
func (s *Server) Decaps(_ context.Context, req *api.DecapsRequest) (*api.DecapsResponse, error) {
	if err := protovalidate.Validate(req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}
	if !IsSupportedKemAlgorithm(req.Ciphertext.Algorithm) {
		return nil, status.Errorf(codes.InvalidArgument, "unsupported ciphertext algorithm: %d. Supported algorithms: %s", req.Ciphertext.Algorithm, SupportedKemAlgorithmsString())
	}

	kemUUID, err := uuid.Parse(req.KeyHandle.Handle)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid key_handle.handle: %v", err)
	}

	encapsulatedKey := req.Ciphertext.Ciphertext
	if len(encapsulatedKey) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "ciphertext.ciphertext must not be empty")
	}
	aad := decapsAADContext(kemUUID, req.Ciphertext.Algorithm)

	// Look up the binding UUID for this KEM key.
	bindingUUID, ok := s.LookupBindingUUID(kemUUID)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "KEM key handle not found: %s", kemUUID)
	}

	// Decapsulate and reseal via KPS.
	sealEnc, sealedCT, err := s.keyProtectionService.DecapAndSeal(kemUUID, encapsulatedKey, aad)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to decap and seal: %v", err)
	}

	// Open the sealed secret using the binding key via WSD KCC.
	plaintext, err := s.workloadService.Open(bindingUUID, sealEnc, sealedCT, aad)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to open sealed secret: %v", err)
	}

	// Return the shared secret.
	return &api.DecapsResponse{
		SharedSecret: &keymanager.KemSharedSecret{
			Algorithm: req.Ciphertext.Algorithm,
			Secret:    plaintext,
		},
	}, nil
}

// GenerateKey handles the creation of new key pairs for workload environments.
func (s *Server) GenerateKey(_ context.Context, req *api.GenerateKeyRequest) (*api.GenerateKeyResponse, error) {
	if req == nil || req.Algorithm == nil || req.Algorithm.Params == nil {
		return nil, status.Errorf(codes.InvalidArgument, "algorithm details cannot be empty")
	}
	if err := protovalidate.Validate(req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}

	switch req.Algorithm.Type {
	case "kem":
		return s.generateKEMKey(req)
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported algorithm type: %q. Only 'kem' is supported", req.Algorithm.Type)
	}
}

func (s *Server) generateKEMKey(req *api.GenerateKeyRequest) (*api.GenerateKeyResponse, error) {
	// Validate algorithm.
	if req.Algorithm.GetParams() == nil || !IsSupportedKemAlgorithm(req.Algorithm.GetParams().GetKemId()) {
		return nil, status.Errorf(codes.InvalidArgument, "unsupported ciphertext algorithm. Supported algorithms: %s", SupportedKemAlgorithmsString())
	}

	// Construct the full HPKE algorithm suite based on the requested KEM.
	// We currently only support one suite.
	algo, err := KemToHpkeAlgorithm(req.Algorithm.GetParams().GetKemId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to convert KEM algorithm to HPKE algorithm: %v", err)
	}

	// Generate binding keypair via WSD KCC FFI.
	bindingUUID, bindingPubKey, err := s.workloadService.GenerateBindingKeypair(algo, req.Lifespan)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate binding keypair: %v", err)
	}

	// Generate KEM keypair via KPS KOL, passing the binding public key.
	kemUUID, kemPubKey, err := s.keyProtectionService.GenerateKEMKeypair(algo, bindingPubKey, req.Lifespan)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate KEM keypair: %v", err)
	}

	// Store the KEM UUID → Binding UUID mapping.
	s.mu.Lock()
	s.kemToBindingMap[kemUUID] = bindingUUID
	s.mu.Unlock()

	// Return KEM UUID to workload.
	return &api.GenerateKeyResponse{
		KeyHandle: &keymanager.KeyHandle{Handle: kemUUID.String()},
		PubKey: &keymanager.PubKeyInfo{
			Algorithm: &keymanager.AlgorithmDetails{
				Type: req.Algorithm.Type,
				Params: &keymanager.AlgorithmParams{
					Params: &keymanager.AlgorithmParams_KemId{
						KemId: req.Algorithm.GetParams().GetKemId(),
					},
				},
			},
			PublicKey: kemPubKey,
		},
		KeyProtectionMechanism: keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM_EMULATED.String(),
		ExpirationTime:         float64(time.Now().Unix()) + float64(req.Lifespan),
	}, nil
}

// GetCapabilities returns the list of supported cryptographic operations and HPKE suites.
func (s *Server) GetCapabilities(_ context.Context, req *api.GetCapabilitiesRequest) (*api.GetCapabilitiesResponse, error) {
	if err := protovalidate.Validate(req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}

	var supportedAlgos []*keymanager.SupportedAlgorithm
	for _, algo := range SupportedKemAlgorithms {
		supportedAlgos = append(supportedAlgos, &keymanager.SupportedAlgorithm{
			Algorithm: &keymanager.AlgorithmDetails{
				Type: "kem",
				Params: &keymanager.AlgorithmParams{
					Params: &keymanager.AlgorithmParams_KemId{
						KemId: algo,
					},
				},
			},
		})
	}

	return &api.GetCapabilitiesResponse{
		SupportedAlgorithms: supportedAlgos,
	}, nil
}

// EnumerateKeys lists all available cryptographic keys currently registered with the Key Protection Service.
func (s *Server) EnumerateKeys(_ context.Context, req *api.EnumerateKeysRequest) (*api.EnumerateKeysResponse, error) {
	if err := protovalidate.Validate(req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}
	keys, _, err := s.keyProtectionService.EnumerateKEMKeys(100, 0)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to enumerate keys: %v", err)
	}

	keyInfos := make([]*api.KeyInfo, 0, len(keys))
	for _, key := range keys {
		var kemAlgo keymanager.KemAlgorithm
		if key.Algorithm != nil {
			kemAlgo = key.Algorithm.Kem
		}

		keyInfos = append(keyInfos, &api.KeyInfo{
			KeyHandle: &keymanager.KeyHandle{Handle: key.ID.String()},
			PubKey: &keymanager.PubKeyInfo{
				Algorithm: &keymanager.AlgorithmDetails{
					Type: "kem",
					Params: &keymanager.AlgorithmParams{
						Params: &keymanager.AlgorithmParams_KemId{
							KemId: kemAlgo,
						},
					},
				},
				PublicKey: key.KEMPubKey,
			},
			KeyProtectionMechanism: keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM_EMULATED.String(),
			ExpirationTime:         float64(time.Now().Unix()) + float64(key.RemainingLifespanSecs),
		})
	}

	return &api.EnumerateKeysResponse{
		KeyInfos: keyInfos,
	}, nil
}

// Destroy deletes a registered cryptographic keypair permanently.
func (s *Server) Destroy(_ context.Context, req *api.DestroyRequest) (*api.DestroyResponse, error) {
	if err := protovalidate.Validate(req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}
	kemUUID, err := uuid.Parse(req.KeyHandle.Handle)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid key handle: %v", err)
	}

	// Look up the binding UUID for this KEM key.
	bindingUUID, ok := s.LookupBindingUUID(kemUUID)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "KEM key handle not found: %s", kemUUID)
	}

	errKps := s.keyProtectionService.DestroyKEMKey(kemUUID)
	errWs := s.workloadService.DestroyBindingKey(bindingUUID)

	// Remove the mapping.
	s.mu.Lock()
	delete(s.kemToBindingMap, kemUUID)
	s.mu.Unlock()

	if err := errors.Join(errKps, errWs); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to destroy keys: %v", err)
	}

	return &api.DestroyResponse{}, nil
}

// handleGetBindingKeyClaims returns the claims for a binding key identified by its KEM UUID.
func (s *Server) handleGetBindingKeyClaims(id uuid.UUID) (*keymanager.KeyClaims, error) {
	// Key ID Lookup. The orchestration layer will look-up the key_handle
	// in its ActiveKeyRegistry to find the Binding Key ID.
	bindingID, ok := s.LookupBindingUUID(id)
	if !ok {
		return nil, fmt.Errorf("binding key ID not found for key handle: %s", id)
	}

	// Key Metadata Lookup.
	pubKey, algo, err := s.workloadService.GetBindingKey(bindingID)
	if err != nil {
		return nil, fmt.Errorf("failed to get binding key: %w", err)
	}

	// Create KeyClaims
	claims := &keymanager.KeyClaims{
		Claims: &keymanager.KeyClaims_VmBindingClaims{
			VmBindingClaims: &keymanager.KeyClaims_VmProtectionBindingClaims{
				BindingPubKey: &keymanager.HpkePublicKey{
					Algorithm: algo,
					PublicKey: pubKey,
				},
			},
		},
	}
	return claims, nil
}

// handleGetKEMKeyClaims returns the claims for a KEM key identified by its UUID.
func (s *Server) handleGetKEMKeyClaims(id uuid.UUID) (*keymanager.KeyClaims, error) {
	// Key Metadata Lookup.
	kemPubKey, bindingPubKey, algo, remainingLifespanSecs, err := s.keyProtectionService.GetKEMKey(id)
	if err != nil {
		return nil, fmt.Errorf("failed to get KEM key: %w", err)
	}

	// Calculate remaining time.
	remaining := time.Duration(remainingLifespanSecs) * time.Second

	// Create KeyClaims
	claims := &keymanager.KeyClaims{
		Claims: &keymanager.KeyClaims_VmKeyClaims{
			VmKeyClaims: &keymanager.KeyClaims_VmProtectionKeyClaims{
				KemPubKey: &keymanager.KemPublicKey{
					Algorithm: algo.GetKem(),
					PublicKey: kemPubKey,
				},
				BindingPubKey: &keymanager.HpkePublicKey{
					Algorithm: algo,
					PublicKey: bindingPubKey,
				},
				RemainingLifespan: durationpb.New(remaining),
				ExpirationTime:    float64(time.Now().Unix()) + float64(remainingLifespanSecs),
			},
		},
	}
	return claims, nil
}

// processClaims is a background worker that processes key claims requests from claimsChan.
func (s *Server) processClaims() {
	for call := range s.claimsChan {
		result := s.handleGetClaims(call.Request)

		select {
		case call.RespChan <- result:
		case <-time.After(ClaimsResponseTimeout):
			log.Printf("processClaims: timed out sending response for key %s", call.Request.GetKeyHandle().GetHandle())
		}
	}
}

// handleGetClaims processes a single GetKeyClaimsRequest and returns the result.
func (s *Server) handleGetClaims(req *keymanager.GetKeyClaimsRequest) *ClaimsResult {
	keyHandle := req.GetKeyHandle().GetHandle()
	keyType := req.GetKeyType()

	id, err := uuid.Parse(keyHandle)
	if err != nil {
		return &ClaimsResult{Err: fmt.Errorf("failed to retrieve key claims: %w", err)}
	}

	var claims *keymanager.KeyClaims
	switch keyType {
	case keymanager.KeyType_KEY_TYPE_VM_PROTECTION_BINDING:
		claims, err = s.handleGetBindingKeyClaims(id)
		if err != nil {
			return &ClaimsResult{Err: fmt.Errorf("failed to retrieve binding key claims: %w", err)}
		}

	case keymanager.KeyType_KEY_TYPE_VM_PROTECTION_KEY:
		claims, err = s.handleGetKEMKeyClaims(id)
		if err != nil {
			return &ClaimsResult{Err: fmt.Errorf("failed to retrieve VM protection key claims: %w", err)}
		}
	default:
		return &ClaimsResult{Err: fmt.Errorf("unsupported key type: %v", keyType)}
	}

	return &ClaimsResult{Reply: claims}
}

// GetKeyClaims enqueues request for getting key claims to claims channel.
func (s *Server) GetKeyClaims(ctx context.Context, keyHandle string, keyType keymanager.KeyType) (*keymanager.KeyClaims, error) {
	respChan := make(chan *ClaimsResult, 1)
	req := &keymanager.GetKeyClaimsRequest{
		KeyHandle: &keymanager.KeyHandle{Handle: keyHandle},
		KeyType:   keyType,
	}
	select {
	case s.claimsChan <- &ClaimsCall{Request: req, RespChan: respChan}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(ClaimsRequestTimeout):
		return nil, fmt.Errorf("failed to send request: claims channel is full or worker is stuck")
	}
	select {
	case result := <-respChan:
		if result.Err != nil {
			return nil, fmt.Errorf("worker error: %w", result.Err)
		}
		return result.Reply, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(ClaimsResponseTimeout):
		return nil, fmt.Errorf("timed out waiting for processClaims to respond for key: %s", keyHandle)
	}
}
