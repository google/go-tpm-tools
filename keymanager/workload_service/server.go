// Package workloadservice implements the Key Orchestration Layer (KOL) for the
// Workload Service Daemon (WSD). It provides an HTTP server on a unix socket
// exposing key generation endpoints.
package workloadservice

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/durationpb"

	kps "github.com/google/go-tpm-tools/keymanager/key_protection_service"
	kpscc "github.com/google/go-tpm-tools/keymanager/key_protection_service/key_custody_core"
	keymanager "github.com/google/go-tpm-tools/keymanager/km_common/proto"
	wskcc "github.com/google/go-tpm-tools/keymanager/workload_service/key_custody_core"
)

// WorkloadService defines the interface for generating binding keypairs.
type WorkloadService interface {
	GenerateBindingKeypair(algo *keymanager.HpkeAlgorithm, lifespanSecs uint64) (uuid.UUID, []byte, error)
	GetBindingKey(id uuid.UUID) ([]byte, error)
}
type kpsBackend struct{}

type workloadService struct{}

func (r *workloadService) GenerateBindingKeypair(algo *keymanager.HpkeAlgorithm, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	return wskcc.GenerateBindingKeypair(algo, lifespanSecs)
}

func (r *workloadService) GetBindingKey(id uuid.UUID) ([]byte, error) {
	return wskcc.GetBindingKey(id)
}

func (b *kpsBackend) GenerateKEMKeypair(algo *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	return kpscc.GenerateKEMKeypair(algo, bindingPubKey, lifespanSecs)
}

func (b *kpsBackend) GetKemKey(id uuid.UUID) ([]byte, []byte, uint64, error) {
	return kpscc.GetKemKey(id)
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

// KeyHandle represents a key handle returned from the API.
type KeyHandle struct {
	Handle string `json:"handle"`
}

// ProtoDuration represents a google.protobuf.Duration in JSON (e.g. "3600s").
type ProtoDuration struct {
	Seconds uint64
}

// UnmarshalJSON parses a proto3 Duration JSON number (as seconds).
func (d *ProtoDuration) UnmarshalJSON(data []byte) error {
	var v float64
	if err := json.Unmarshal(data, &v); err != nil {
		return fmt.Errorf("duration must be a numeric value (seconds): %w", err)
	}
	if v < 0 || v > math.MaxUint64 {
		return fmt.Errorf("duration %f out of range", v)
	}
	d.Seconds = uint64(v)
	return nil
}

// MarshalJSON encodes as a proto3 Duration JSON number (as seconds).
func (d ProtoDuration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.Seconds)
}

// GenerateKemRequest is the JSON body for POST /v1/keys:generate_kem.
type GenerateKemRequest struct {
	Algorithm              KemAlgorithm           `json:"algorithm"`
	KeyProtectionMechanism KeyProtectionMechanism `json:"key_protection_mechanism"`
	Lifespan               ProtoDuration          `json:"lifespan"`
}

// GenerateKemResponse is returned by POST /v1/keys:generate_kem.
type GenerateKemResponse struct {
	KeyHandle KeyHandle `json:"key_handle"`
}

// AlgorithmParams represents the parameters for a specific algorithm type.
type AlgorithmParams struct {
	KemID KemAlgorithm `json:"kem_id"`
}

// AlgorithmDetails captures type and specific params.
type AlgorithmDetails struct {
	Type   string          `json:"type"`
	Params AlgorithmParams `json:"params"`
}

// SupportedAlgorithm represents a single algorithm capability.
type SupportedAlgorithm struct {
	Algorithm AlgorithmDetails `json:"algorithm"`
}

// GetCapabilitiesResponse represents the JSON body for GET /v1/capabilities.
type GetCapabilitiesResponse struct {
	SupportedAlgorithms []SupportedAlgorithm `json:"supported_algorithms"`
}

// Server is the WSD HTTP server.
type Server struct {
	keyProtectionService kps.KeyProtectionService
	workloadService      WorkloadService

	mu              sync.RWMutex
	kemToBindingMap map[uuid.UUID]uuid.UUID

	claimsChan chan *ClaimsCall

	httpServer *http.Server
	listener   net.Listener
	// todo: add logging mechanism here
}

// New creates a new WSD Server listening on the given unix socket path.
func New(_ context.Context, socketPath string) (*Server, error) {
	kpsService := kps.NewService(&kpsBackend{})
	return NewServer(kpsService, &workloadService{}, socketPath)
}

// NewServer creates a new WSD server with the given dependencies.
func NewServer(keyProtectionService kps.KeyProtectionService, workloadService WorkloadService, socketPath string) (*Server, error) {
	s := &Server{
		keyProtectionService: keyProtectionService,
		workloadService:      workloadService,
		kemToBindingMap:      make(map[uuid.UUID]uuid.UUID),
		mu:                   sync.RWMutex{},
		claimsChan:           make(chan *ClaimsCall, 100),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/keys:generate_kem", s.handleGenerateKem)
	mux.HandleFunc("GET /v1/capabilities", s.handleGetCapabilities)

	s.httpServer = &http.Server{Handler: mux}

	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on unix socket %s: %w", socketPath, err)
	}
	s.listener = ln

	go s.processClaims()

	return s, nil
}

// Serve starts the HTTP server listening on the given unix socket path.
func (s *Server) Serve() error {
	return s.httpServer.Serve(s.listener)
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
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

func (s *Server) handleGenerateKem(w http.ResponseWriter, r *http.Request) {
	var req GenerateKemRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	// Validate algorithm.
	if !req.Algorithm.IsSupported() {
		writeError(w, fmt.Sprintf("unsupported algorithm: %s. Supported algorithms: %s", req.Algorithm, SupportedKemAlgorithmsString()), http.StatusBadRequest)
		return
	}

	// Validate keyProtectionMechanism.
	if !req.KeyProtectionMechanism.IsSupported() {
		writeError(w, fmt.Sprintf("unsupported keyProtectionMechanism: %s", req.KeyProtectionMechanism), http.StatusBadRequest)
		return
	}

	// Validate lifespan is positive.
	if req.Lifespan.Seconds == 0 {
		writeError(w, "lifespan must be greater than 0s", http.StatusBadRequest)
		return
	}

	// Construct the full HPKE algorithm suite based on the requested KEM.
	// We currently only support one suite.
	algo, err := req.Algorithm.ToHpkeAlgorithm()
	if err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Step 1: Generate binding keypair via WSD KCC FFI.
	bindingUUID, bindingPubKey, err := s.workloadService.GenerateBindingKeypair(algo, req.Lifespan.Seconds)
	if err != nil {
		writeError(w, fmt.Sprintf("failed to generate binding keypair: %v", err), http.StatusInternalServerError)
		return
	}

	// Step 2: Generate KEM keypair via KPS KOL, passing the binding public key.
	kemUUID, _, err := s.keyProtectionService.GenerateKEMKeypair(algo, bindingPubKey, req.Lifespan.Seconds)
	if err != nil {
		writeError(w, fmt.Sprintf("failed to generate KEM keypair: %v", err), http.StatusInternalServerError)
		return
	}

	// Step 3: Store the KEM UUID → Binding UUID mapping.
	s.mu.Lock()
	s.kemToBindingMap[kemUUID] = bindingUUID
	s.mu.Unlock()

	// Step 4: Return KEM UUID to workload.
	resp := GenerateKemResponse{
		KeyHandle: KeyHandle{Handle: kemUUID.String()},
	}
	writeJSON(w, resp, http.StatusOK)
}

func (s *Server) handleGetCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var supportedAlgos []SupportedAlgorithm
	for _, algo := range SupportedKemAlgorithms {
		supportedAlgos = append(supportedAlgos, SupportedAlgorithm{
			Algorithm: AlgorithmDetails{
				Type: "kem",
				Params: AlgorithmParams{
					KemID: algo,
				},
			},
		})
	}

	resp := GetCapabilitiesResponse{
		SupportedAlgorithms: supportedAlgos,
	}

	writeJSON(w, resp, http.StatusOK)
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, v any, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, message string, code int) {
	writeJSON(w, map[string]string{"error": message}, code)
}

// GetBindingKeyClaims returns the claims for a binding key identified by its UUID.
func (s *Server) GetBindingKeyClaims(id uuid.UUID) (*keymanager.KeyClaims, error) {
	// Step 1: Key ID Lookup. The orchestration layer will look-up the key_handle
	// in its ActiveKeyRegistry to find the Binding Key ID.
	bindingID := id
	if bid, ok := s.LookupBindingUUID(id); ok {
		bindingID = bid
	}

	// Step 2: Key Metadata Lookup.
	pubKey, err := s.workloadService.GetBindingKey(bindingID)
	if err != nil {
		return nil, fmt.Errorf("failed to get binding key: %w", err)
	}

	// Step 3: Create KeyClaims
	claims := &keymanager.KeyClaims{
		Claims: &keymanager.KeyClaims_VmBindingClaims{
			VmBindingClaims: &keymanager.KeyClaims_VmProtectionBindingClaims{
				BindingPubKey: &keymanager.HpkePublicKey{
					Algorithm: &keymanager.HpkeAlgorithm{
						Kem:  keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256,
						Kdf:  keymanager.KdfAlgorithm_KDF_ALGORITHM_HKDF_SHA256,
						Aead: keymanager.AeadAlgorithm_AEAD_ALGORITHM_AES_256_GCM,
					},
					PublicKey: pubKey,
				},
			},
		},
	}
	return claims, nil
}

// GetKemKeyClaims returns the claims for a KEM key identified by its UUID.
func (s *Server) GetKemKeyClaims(id uuid.UUID) (*keymanager.KeyClaims, error) {
	// Step 1: Key Metadata Lookup.
	kemPubKey, bindingPubKey, deleteAfter, err := s.keyProtectionService.GetKemKey(id)
	if err != nil {
		return nil, fmt.Errorf("failed to get KEM key: %w", err)
	}

	// Step 2: Calculate remaining time.
	remaining := time.Duration(0)
	if deleteAfter > 0 {
		expiry := time.Unix(int64(deleteAfter), 0)
		remaining = max(time.Until(expiry), 0)
	}

	// Step 3: Create KeyClaims
	claims := &keymanager.KeyClaims{
		Claims: &keymanager.KeyClaims_VmKeyClaims{
			VmKeyClaims: &keymanager.KeyClaims_VmProtectionKeyClaims{
				KemPubKey: &keymanager.KemPublicKey{
					Algorithm: keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256,
					PublicKey: kemPubKey,
				},
				BindingPubKey: &keymanager.HpkePublicKey{
					Algorithm: &keymanager.HpkeAlgorithm{
						Kem:  keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256,
						Kdf:  keymanager.KdfAlgorithm_KDF_ALGORITHM_HKDF_SHA256,
						Aead: keymanager.AeadAlgorithm_AEAD_ALGORITHM_AES_256_GCM,
					},
					PublicKey: bindingPubKey,
				},
				RemainingLifespan: durationpb.New(remaining),
			},
		},
	}
	return claims, nil
}

func (s *Server) processClaims() {
	for call := range s.claimsChan {
		req := call.Request
		keyHandle := req.GetKeyHandle().GetHandle()
		keyType := req.GetKeyType()

		id, err := uuid.Parse(keyHandle)
		if err != nil {
			call.RespChan <- &ClaimsResult{Err: fmt.Errorf("failed to retrieve key claims: %w", err)}
			continue
		}
		var claims *keymanager.KeyClaims
		switch keyType {
		case keymanager.KeyType_KEY_TYPE_VM_PROTECTION_BINDING:
			claims, err = s.GetBindingKeyClaims(id)
			if err != nil {
				call.RespChan <- &ClaimsResult{Err: fmt.Errorf("failed to retrieve key claims: %w", err)}
				continue
			}

		case keymanager.KeyType_KEY_TYPE_VM_PROTECTION_KEY:
			claims, err = s.GetKemKeyClaims(id)
			if err != nil {
				call.RespChan <- &ClaimsResult{Err: fmt.Errorf("failed to retrieve key claims: %w", err)}
				continue
			}
		default:
			call.RespChan <- &ClaimsResult{Err: fmt.Errorf("unsupported key type: %v", keyType)}
			continue
		}

		call.RespChan <- &ClaimsResult{Reply: claims}
	}
}
