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
	"strconv"
	"strings"
	"sync"

	"github.com/google/uuid"
)

// BindingKeyGenerator generates binding keypairs via the WSD KCC FFI.
type BindingKeyGenerator interface {
	GenerateBindingKeypair(lifespanSecs uint64) (uuid.UUID, []byte, error)
}

// KEMKeyGenerator generates KEM keypairs via the KPS KOL/KCC.
type KEMKeyGenerator interface {
	GenerateKEMKeypair(bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error)
}

// KeyHandle represents a key handle returned from the API.
type KeyHandle struct {
	Handle string `json:"handle"`
}

// ProtoDuration represents a google.protobuf.Duration in JSON (e.g. "3600s").
type ProtoDuration struct {
	Seconds uint64
}

// UnmarshalJSON parses a proto3 Duration JSON string (e.g. "300s", "1.5s").
func (d *ProtoDuration) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("duration must be a string: %w", err)
	}
	if !strings.HasSuffix(s, "s") {
		return fmt.Errorf("duration %q missing trailing 's'", s)
	}
	v, err := strconv.ParseFloat(strings.TrimSuffix(s, "s"), 64)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	if v < 0 || v > math.MaxUint64 {
		return fmt.Errorf("duration %q out of range", s)
	}
	d.Seconds = uint64(v)
	return nil
}

// MarshalJSON encodes as a proto3 Duration JSON string.
func (d ProtoDuration) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("%ds", d.Seconds))
}

// GenerateKemRequest is the JSON body for POST /v1/keys:generate_kem.
type GenerateKemRequest struct {
	Algorithm              KemAlgorithm           `json:"algorithm"`
	KeyProtectionMechanism KeyProtectionMechanism `json:"key_protection_mechanism"`
	Lifespan               ProtoDuration          `json:"lifespan"`
}

// GenerateKemResponse is returned by POST /v1/keys:generate.
type GenerateKemResponse struct {
	KeyHandle KeyHandle `json:"key_handle"`
}

// Server is the WSD HTTP server.
type Server struct {
	bindingGen BindingKeyGenerator
	kemGen     KEMKeyGenerator

	mu              sync.RWMutex
	kemToBindingMap map[uuid.UUID]uuid.UUID

	httpServer *http.Server
	listener   net.Listener
}

// NewServer creates a new WSD server with the given dependencies.
func NewServer(bindingGen BindingKeyGenerator, kemGen KEMKeyGenerator) *Server {
	s := &Server{
		bindingGen:      bindingGen,
		kemGen:          kemGen,
		kemToBindingMap: make(map[uuid.UUID]uuid.UUID),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/keys:generate_kem", s.handleGenerateKem)

	s.httpServer = &http.Server{Handler: mux}
	return s
}

// Serve starts the HTTP server listening on the given unix socket path.
func (s *Server) Serve(socketPath string) error {
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
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req GenerateKemRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	// Validate algorithm: only DHKEM_X25519_HKDF_SHA256 supported.
	if req.Algorithm != KemAlgorithmDHKEMX25519HKDFSHA256 {
		http.Error(
			w,
			fmt.Sprintf(
				"unsupported algorithm: only KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256 (%d) is supported",
				KemAlgorithmDHKEMX25519HKDFSHA256,
			),
			http.StatusBadRequest,
		)
		return
	}

	// Validate keyProtectionMechanism: only KEY_PROTECTION_VM supported.
	if req.KeyProtectionMechanism != KeyProtectionMechanismVM {
		http.Error(
			w,
			fmt.Sprintf(
				"unsupported keyProtectionMechanism: only KEY_PROTECTION_VM (%d) is supported",
				KeyProtectionMechanismVM,
			),
			http.StatusBadRequest,
		)
		return
	}

	// Validate lifespan is positive.
	if req.Lifespan.Seconds == 0 {
		http.Error(w, "lifespan must be greater than 0s", http.StatusBadRequest)
		return
	}

	// Step 1: Generate binding keypair via WSD KCC FFI.
	bindingUUID, bindingPubKey, err := s.bindingGen.GenerateBindingKeypair(req.Lifespan.Seconds)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to generate binding keypair: %v", err), http.StatusInternalServerError)
		return
	}

	// Step 2: Generate KEM keypair via KPS KOL, passing the binding public key.
	kemUUID, _, err := s.kemGen.GenerateKEMKeypair(bindingPubKey, req.Lifespan.Seconds)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to generate KEM keypair: %v", err), http.StatusInternalServerError)
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
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
