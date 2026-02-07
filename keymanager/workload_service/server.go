// Package workload_service implements the Key Orchestration Layer (KOL) for the
// Workload Service Daemon (WSD). It provides an HTTP server on a unix socket
// exposing key generation endpoints.
package workload_service

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/google/uuid"
)

// BindingKeyGenerator generates binding keypairs via the WSD KCC FFI.
type BindingKeyGenerator interface {
	GenerateBindingKeypair() (uuid.UUID, []byte, error)
}

// KEMKeyGenerator generates KEM keypairs via the KPS KOL/KCC.
type KEMKeyGenerator interface {
	GenerateKEMKeypair(bindingPubKey []byte) (uuid.UUID, []byte, error)
}

// GenerateKeysResponse is returned by POST /keys:generate.
type GenerateKeysResponse struct {
	KEMKeyHandle string `json:"kemKeyHandle"`
}

// ActiveKeyRegistry manages the mapping between KEM keys and Binding keys.
type ActiveKeyRegistry interface {
	// Register records the association between a KEM key and its Binding key.
	Register(kemUUID, bindingUUID uuid.UUID)
	// GetBinding returns the binding UUID associated with the given KEM UUID.
	GetBinding(kemUUID uuid.UUID) (uuid.UUID, bool)
	// Unregister removes the mapping for a KEM key.
	Unregister(kemUUID uuid.UUID)
}

// MemoryActiveKeyRegistry is a thread-safe in-memory implementation of ActiveKeyRegistry.
type MemoryActiveKeyRegistry struct {
	mu   sync.RWMutex
	data map[uuid.UUID]uuid.UUID
}

// NewMemoryActiveKeyRegistry creates a new MemoryActiveKeyRegistry.
func NewMemoryActiveKeyRegistry() *MemoryActiveKeyRegistry {
	return &MemoryActiveKeyRegistry{
		data: make(map[uuid.UUID]uuid.UUID),
	}
}

// Register records the association between a KEM key and its Binding key.
func (r *MemoryActiveKeyRegistry) Register(kemUUID, bindingUUID uuid.UUID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.data[kemUUID] = bindingUUID
}

// GetBinding returns the binding UUID associated with the given KEM UUID.
func (r *MemoryActiveKeyRegistry) GetBinding(kemUUID uuid.UUID) (uuid.UUID, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	val, ok := r.data[kemUUID]
	return val, ok
}

// Unregister removes the mapping for a KEM key.
func (r *MemoryActiveKeyRegistry) Unregister(kemUUID uuid.UUID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.data, kemUUID)
}

// Server is the WSD HTTP server.
type Server struct {
	bindingGen BindingKeyGenerator
	kemGen     KEMKeyGenerator
	registry   ActiveKeyRegistry

	httpServer *http.Server
	listener   net.Listener
}

// NewServer creates a new WSD server with the given dependencies.
func NewServer(bindingGen BindingKeyGenerator, kemGen KEMKeyGenerator) *Server {
	s := &Server{
		bindingGen: bindingGen,
		kemGen:     kemGen,
		registry:   NewMemoryActiveKeyRegistry(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/keys:generate", s.handleGenerateKeys)

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
	return s.registry.GetBinding(kemUUID)
}

func (s *Server) handleGenerateKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Step 1: Generate binding keypair via WSD KCC FFI.
	bindingUUID, bindingPubKey, err := s.bindingGen.GenerateBindingKeypair()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to generate binding keypair: %v", err), http.StatusInternalServerError)
		return
	}

	// Step 2: Generate KEM keypair via KPS KOL, passing the binding public key.
	kemUUID, _, err := s.kemGen.GenerateKEMKeypair(bindingPubKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to generate KEM keypair: %v", err), http.StatusInternalServerError)
		return
	}

	// Step 3: Store the KEM UUID → Binding UUID mapping.
	s.registry.Register(kemUUID, bindingUUID)

	// Step 4: Return KEM UUID to workload.
	resp := GenerateKeysResponse{
		KEMKeyHandle: kemUUID.String(),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
