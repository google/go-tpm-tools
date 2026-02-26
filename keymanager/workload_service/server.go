// Package workloadservice implements the Key Orchestration Layer (KOL) for the
// Workload Service Daemon (WSD). It provides an HTTP server on a unix socket
// exposing cryptographic and key management endpoints.
package workloadservice

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/google/uuid"

	kpscc "github.com/google/go-tpm-tools/keymanager/key_protection_service/key_custody_core"
	keymanager "github.com/google/go-tpm-tools/keymanager/km_common/proto"
	wskcc "github.com/google/go-tpm-tools/keymanager/workload_service/key_custody_core"
)

// WorkloadService defines the interface for generating binding keypairs.
type WorkloadService interface {
	GenerateBindingKeypair(algo *keymanager.HpkeAlgorithm, lifespanSecs uint64) (uuid.UUID, []byte, error)
}
type keyProtectionService struct{}

// KeyProtectionService defines the interface for generating KEM keypairs.
type KeyProtectionService interface {
	GenerateKEMKeypair(algo *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error)
	EnumerateKEMKeys(limit, offset int) ([]kpscc.KEMKeyInfo, bool, error)
}
type workloadService struct{}

func (r *workloadService) GenerateBindingKeypair(algo *keymanager.HpkeAlgorithm, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	return wskcc.GenerateBindingKeypair(algo, lifespanSecs)
}

func (r *keyProtectionService) GenerateKEMKeypair(algo *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	return kpscc.GenerateKEMKeypair(algo, bindingPubKey, lifespanSecs)
}

func (r *keyProtectionService) EnumerateKEMKeys(limit, offset int) ([]kpscc.KEMKeyInfo, bool, error) {
	return kpscc.EnumerateKEMKeys(limit, offset)
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

// GenerateKeyRequest is the JSON body for POST /v1/keys:generate_key.
type GenerateKeyRequest struct {
	Algorithm AlgorithmDetails `json:"algorithm"`
	Lifespan  ProtoDuration    `json:"lifespan"`
}

// GenerateKeyResponse is returned by POST /v1/keys:generate_key.
type GenerateKeyResponse struct {
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

// EnumerateKeysResponse represents the response for GET /v1/keys.
type EnumerateKeysResponse struct {
	KeyInfos []KeyInfo `json:"key_infos"`
}

// KeyInfo contains information about a single key.
type KeyInfo struct {
	KeyHandle         KeyHandle     `json:"key_handle"`
	PubKey            PubKeyInfo    `json:"pub_key"`
	RemainingLifespan ProtoDuration `json:"remaining_lifespan"`
}

// PubKeyInfo contains the public key and its algorithm.
type PubKeyInfo struct {
	Algorithm AlgorithmDetails `json:"algorithm"`
	PublicKey string           `json:"public_key"` // Base64 encoded public key
}

// Server is the WSD HTTP server.
type Server struct {
	keyProtectionService KeyProtectionService
	workloadService      WorkloadService

	mu              sync.RWMutex
	kemToBindingMap map[uuid.UUID]uuid.UUID

	httpServer *http.Server
	listener   net.Listener
	// todo: add logging mechanism here
}

// New creates a new WSD Server listening on the given unix socket path.
func New(_ context.Context, socketPath string) (*Server, error) {
	return NewServer(&keyProtectionService{}, &workloadService{}, socketPath)
}

// NewServer creates a new WSD server with the given dependencies.
func NewServer(keyProtectionService KeyProtectionService, workloadService WorkloadService, socketPath string) (*Server, error) {
	s := &Server{
		keyProtectionService: keyProtectionService,
		workloadService:      workloadService,
		kemToBindingMap:      make(map[uuid.UUID]uuid.UUID),
		mu:                   sync.RWMutex{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/keys:generate_key", s.handleGenerateKey)
	mux.HandleFunc("GET /v1/capabilities", s.handleGetCapabilities)
	mux.HandleFunc("GET /v1/keys", s.handleEnumerateKeys)

	s.httpServer = &http.Server{Handler: mux}

	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on unix socket %s: %w", socketPath, err)
	}
	s.listener = ln
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

func (s *Server) handleGenerateKey(w http.ResponseWriter, r *http.Request) {
	var req GenerateKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	// Validate lifespan is positive.
	if req.Lifespan.Seconds == 0 {
		writeError(w, "lifespan must be greater than 0s", http.StatusBadRequest)
		return
	}

	switch req.Algorithm.Type {
	case "kem":
		s.generateKEMKey(w, req)
	default:
		writeError(w, fmt.Sprintf("unsupported algorithm type: %q. Only 'kem' is supported.", req.Algorithm.Type), http.StatusBadRequest)
	}
}

func (s *Server) generateKEMKey(w http.ResponseWriter, req GenerateKeyRequest) {
	// Validate algorithm.
	if !req.Algorithm.Params.KemID.IsSupported() {
		writeError(w, fmt.Sprintf("unsupported algorithm: %s. Supported algorithms: %s", req.Algorithm.Params.KemID, SupportedKemAlgorithmsString()), http.StatusBadRequest)
		return
	}

	// Construct the full HPKE algorithm suite based on the requested KEM.
	// We currently only support one suite.
	algo, err := req.Algorithm.Params.KemID.ToHpkeAlgorithm()
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
	resp := GenerateKeyResponse{
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

func (s *Server) handleEnumerateKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	keys, _, err := s.keyProtectionService.EnumerateKEMKeys(100, 0)
	if err != nil {
		writeError(w, fmt.Sprintf("failed to enumerate keys: %v", err), http.StatusInternalServerError)
		return
	}

	var keyInfos []KeyInfo
	for _, key := range keys {
		kemAlgo := KemAlgorithmUnspecified
		if key.Algorithm != nil {
			switch key.Algorithm.Kem {
			case keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256:
				kemAlgo = KemAlgorithmDHKEMX25519HKDFSHA256
			}
		}

		keyInfos = append(keyInfos, KeyInfo{
			KeyHandle: KeyHandle{Handle: key.ID.String()},
			PubKey: PubKeyInfo{
				Algorithm: AlgorithmDetails{
					Type: "kem",
					Params: AlgorithmParams{
						KemID: kemAlgo,
					},
				},
				PublicKey: base64.StdEncoding.EncodeToString(key.KEMPubKey),
			},
			RemainingLifespan: ProtoDuration{Seconds: key.RemainingLifespanSecs},
		})
	}

	if keyInfos == nil {
		keyInfos = make([]KeyInfo, 0) // Ensure empty slice rather than null in JSON
	}

	resp := EnumerateKeysResponse{
		KeyInfos: keyInfos,
	}

	writeJSON(w, resp, http.StatusOK)
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, v any, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, message string, code int) {
	writeJSON(w, map[string]string{"error": message}, code)
}
