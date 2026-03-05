// Package workloadservice implements the Key Orchestration Layer (KOL) for the
// Workload Service Daemon (WSD). It provides an HTTP server on a unix socket
// exposing key management endpoints.
package workloadservice

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
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
	DestroyBindingKey(bindingUUID uuid.UUID) error
	Open(bindingUUID uuid.UUID, enc, ciphertext, aad []byte) ([]byte, error)
}
type keyProtectionService struct{}

// KeyProtectionService defines the interface for generating KEM keypairs.
type KeyProtectionService interface {
	GenerateKEMKeypair(algo *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error)
	DestroyKEMKey(kemUUID uuid.UUID) error
	DecapAndSeal(kemUUID uuid.UUID, encapsulatedKey, aad []byte) (sealEnc []byte, sealedCT []byte, err error)
}
type workloadService struct{}

func (r *workloadService) GenerateBindingKeypair(algo *keymanager.HpkeAlgorithm, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	return wskcc.GenerateBindingKeypair(algo, lifespanSecs)
}

func (r *workloadService) DestroyBindingKey(bindingUUID uuid.UUID) error {
	return wskcc.DestroyBindingKey(bindingUUID)
}

func (r *workloadService) Open(bindingUUID uuid.UUID, enc, ciphertext, aad []byte) ([]byte, error) {
	return wskcc.Open(bindingUUID, enc, ciphertext, aad)
}

func (r *keyProtectionService) GenerateKEMKeypair(algo *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	return kpscc.GenerateKEMKeypair(algo, bindingPubKey, lifespanSecs)
}

func (r *keyProtectionService) DestroyKEMKey(kemUUID uuid.UUID) error {
	return kpscc.DestroyKEMKey(kemUUID)
}

func (r *keyProtectionService) DecapAndSeal(kemUUID uuid.UUID, encapsulatedKey, aad []byte) (sealEnc []byte, sealedCT []byte, err error) {
	return kpscc.DecapAndSeal(kemUUID, encapsulatedKey, aad)
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

// DestroyRequest is the JSON body for POST /v1/keys:destroy.
type DestroyRequest struct {
	KeyHandle KeyHandle `json:"key_handle"`
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

// KemCiphertext carries raw encapsulated key bytes and the KEM algorithm.
type KemCiphertext struct {
	Algorithm  KemAlgorithm `json:"algorithm"`
	Ciphertext string       `json:"ciphertext"` // base64-encoded raw bytes
}

// DecapsRequest is the JSON body for POST /keys:decap.
type DecapsRequest struct {
	KeyHandle  KeyHandle     `json:"key_handle"`
	Ciphertext KemCiphertext `json:"ciphertext"`
}

// KemSharedSecret is the Decaps result payload.
type KemSharedSecret struct {
	Algorithm KemAlgorithm `json:"algorithm"`
	Secret    string       `json:"secret"` // base64-encoded raw bytes
}

// DecapsResponse is returned by POST /v1/keys:decap.
type DecapsResponse struct {
	SharedSecret KemSharedSecret `json:"shared_secret"`
}

// Server is the WSD HTTP server.
type Server struct {
	keyProtectionService KeyProtectionService
	workloadService      WorkloadService
	mu                   sync.RWMutex
	kemToBindingMap      map[uuid.UUID]uuid.UUID

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
	mux.HandleFunc("POST /v1/keys:decap", s.handleDecaps)
	mux.HandleFunc("GET /v1/capabilities", s.handleGetCapabilities)
	mux.HandleFunc("POST /v1/keys:destroy", s.handleDestroy)
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

func decapsAADContext(kemUUID uuid.UUID, algorithm KemAlgorithm) []byte {
	// Bind the KPS->WSD transport ciphertext to this decapsulation context.
	// Note: The AAD context string retains `decaps` as it is part of the internal binding protocol
	// and changing it might affect backward compatibility if keys were already persisted (though lifespan is short).
	// For API alignment, we only change the external endpoint and JSON.
	return []byte(fmt.Sprintf("wsd:keys:decaps:v1:%d:%s", algorithm, kemUUID))
}

func (s *Server) handleDecaps(w http.ResponseWriter, r *http.Request) {

	var req DecapsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	if !req.Ciphertext.Algorithm.IsSupported() {
		http.Error(w, fmt.Sprintf("unsupported ciphertext algorithm: %d. Supported algorithms: %s", req.Ciphertext.Algorithm, SupportedKemAlgorithmsString()), http.StatusBadRequest)
		return
	}

	kemUUID, err := uuid.Parse(req.KeyHandle.Handle)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid key_handle.handle: %v", err), http.StatusBadRequest)
		return
	}

	encapsulatedKey, err := base64.StdEncoding.DecodeString(req.Ciphertext.Ciphertext)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid ciphertext.ciphertext base64: %v", err), http.StatusBadRequest)
		return
	}
	if len(encapsulatedKey) == 0 {
		http.Error(w, "ciphertext.ciphertext must not be empty", http.StatusBadRequest)
		return
	}
	aad := decapsAADContext(kemUUID, req.Ciphertext.Algorithm)

	// Look up the binding UUID for this KEM key.
	bindingUUID, ok := s.LookupBindingUUID(kemUUID)
	if !ok {
		http.Error(w, fmt.Sprintf("KEM key handle not found: %s", kemUUID), http.StatusNotFound)
		return
	}

	// Decapsulate and reseal via KPS.
	sealEnc, sealedCT, err := s.keyProtectionService.DecapAndSeal(kemUUID, encapsulatedKey, aad)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to decap and seal: %v", err), http.StatusInternalServerError)
		return
	}

	// Open the sealed secret using the binding key via WSD KCC.
	plaintext, err := s.workloadService.Open(bindingUUID, sealEnc, sealedCT, aad)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to open sealed secret: %v", err), http.StatusInternalServerError)
		return
	}

	// Return the shared secret.
	resp := DecapsResponse{
		SharedSecret: KemSharedSecret{
			Algorithm: req.Ciphertext.Algorithm,
			Secret:    base64.StdEncoding.EncodeToString(plaintext),
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
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

	// Generate binding keypair via WSD KCC FFI.
	bindingUUID, bindingPubKey, err := s.workloadService.GenerateBindingKeypair(algo, req.Lifespan.Seconds)
	if err != nil {
		writeError(w, fmt.Sprintf("failed to generate binding keypair: %v", err), http.StatusInternalServerError)
		return
	}

	// Generate KEM keypair via KPS KOL, passing the binding public key.
	kemUUID, _, err := s.keyProtectionService.GenerateKEMKeypair(algo, bindingPubKey, req.Lifespan.Seconds)
	if err != nil {
		writeError(w, fmt.Sprintf("failed to generate KEM keypair: %v", err), http.StatusInternalServerError)
		return
	}

	// Store the KEM UUID → Binding UUID mapping.
	s.mu.Lock()
	s.kemToBindingMap[kemUUID] = bindingUUID
	s.mu.Unlock()

	// Return KEM UUID to workload.
	resp := GenerateKeyResponse{
		KeyHandle: KeyHandle{Handle: kemUUID.String()},
	}
	writeJSON(w, resp, http.StatusOK)
}

func (s *Server) handleGetCapabilities(w http.ResponseWriter, _ *http.Request) {

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
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("failed to write JSON response: %v", err)
	}
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, message string, code int) {
	writeJSON(w, map[string]string{"error": message}, code)
}

func (s *Server) handleDestroy(w http.ResponseWriter, r *http.Request) {
	var req DestroyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	kemUUID, err := uuid.Parse(req.KeyHandle.Handle)
	if err != nil {
		writeError(w, fmt.Sprintf("invalid key handle: %v", err), http.StatusBadRequest)
		return
	}

	// Look up the binding UUID for this KEM key.
	bindingUUID, ok := s.LookupBindingUUID(kemUUID)
	if !ok {
		writeError(w, fmt.Sprintf("KEM key handle not found: %s", kemUUID), http.StatusNotFound)
		return
	}

	errKps := s.keyProtectionService.DestroyKEMKey(kemUUID)
	errWs := s.workloadService.DestroyBindingKey(bindingUUID)

	// Remove the mapping.
	s.mu.Lock()
	delete(s.kemToBindingMap, kemUUID)
	s.mu.Unlock()

	if err := errors.Join(errKps, errWs); err != nil {
		writeError(w, fmt.Sprintf("failed to destroy keys: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
