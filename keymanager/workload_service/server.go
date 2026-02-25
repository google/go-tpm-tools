// Package workload_service implements the Key Orchestration Layer (KOL) for the
// Workload Service Daemon (WSD). It provides an HTTP server on a unix socket
// exposing key generation endpoints.
package workload_service

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/google/uuid"

	kpscc "github.com/google/go-tpm-tools/keymanager/key_protection_service/key_custody_core"
	algorithms "github.com/google/go-tpm-tools/keymanager/km_common/proto"
	wskcc "github.com/google/go-tpm-tools/keymanager/workload_service/key_custody_core"
)

// WorkloadService defines the interface for generating binding keypairs.
type WorkloadService interface {
	GenerateBindingKeypair(algo *algorithms.HpkeAlgorithm, lifespanSecs uint64) (uuid.UUID, []byte, error)
}
type keyProtectionService struct{}

// KeyProtectionService defines the interface for generating KEM keypairs.
type KeyProtectionService interface {
	GenerateKEMKeypair(algo *algorithms.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error)
}
type workloadService struct{}

func (r *workloadService) GenerateBindingKeypair(algo *algorithms.HpkeAlgorithm, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	return wskcc.GenerateBindingKeypair(algo, lifespanSecs)
}

func (r *keyProtectionService) GenerateKEMKeypair(algo *algorithms.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	return kpscc.GenerateKEMKeypair(algo, bindingPubKey, lifespanSecs)
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
	keyProtectionService KeyProtectionService
	workloadService      WorkloadService

	mu              sync.RWMutex
	kemToBindingMap map[uuid.UUID]uuid.UUID

	httpServer *http.Server
	listener   net.Listener
	// todo: add logging mechanism here
}

// New creates a new WSD Server
func New(ctx context.Context, unixSock string) *Server {
	s := NewServer(&keyProtectionService{}, &workloadService{})
	return s
}

// NewServer creates a new WSD server with the given dependencies.
func NewServer(keyProtectionService KeyProtectionService, workloadService WorkloadService) *Server {
	s := &Server{
		keyProtectionService: keyProtectionService,
		workloadService:      workloadService,
		kemToBindingMap:      make(map[uuid.UUID]uuid.UUID),
		mu:                   sync.RWMutex{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/keys:generate_kem", s.handleGenerateKem)
	mux.HandleFunc("GET /v1/capabilities", s.handleGetCapabilities)

	s.httpServer = &http.Server{Handler: mux}
	return s
}

// Serve starts the HTTP server listening on the given unix socket path.
func (s *Server) Serve(socketPath string) error {
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on unix socket %s: %w", socketPath, err)
	}
	s.listener = ln
	return s.httpServer.Serve(ln)
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
	json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, message string, code int) {
	writeJSON(w, map[string]string{"error": message}, code)
}
