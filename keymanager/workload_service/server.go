// Package workload_service implements the Key Orchestration Layer (KOL) for the
// Workload Service Daemon (WSD). It provides an HTTP server on a unix socket
// exposing key generation endpoints.
package workload_service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/google/uuid"
)

// BindingKeyGenerator generates binding keypairs via the WSD KCC FFI.
type BindingKeyGenerator interface {
	GenerateBindingKeypair() (uuid.UUID, error)
}

// KEMKeyGenerator generates KEM keypairs via the KPS KOL/KCC.
type KEMKeyGenerator interface {
	GenerateKEMKeypair(bindingPubKey []byte) (uuid.UUID, error)
}

// GenerateBindingKeypairResponse is returned by POST /keys:generateBindingKeypair.
type GenerateBindingKeypairResponse struct {
	BindingKeyHandle string `json:"bindingKeyHandle"`
}

// GenerateKEMKeypairRequest is the body for POST /keys:generateKEMKeypair.
type GenerateKEMKeypairRequest struct {
	BindingPublicKey string `json:"bindingPublicKey"` // base64-encoded
}

// GenerateKEMKeypairResponse is returned by POST /keys:generateKEMKeypair.
type GenerateKEMKeypairResponse struct {
	KEMKeyHandle string `json:"kemKeyHandle"`
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
	mux.HandleFunc("/keys:generateBindingKeypair", s.handleGenerateBindingKeypair)
	mux.HandleFunc("/keys:generateKEMKeypair", s.handleGenerateKEMKeypair)

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

func (s *Server) handleGenerateBindingKeypair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bindingUUID, err := s.bindingGen.GenerateBindingKeypair()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to generate binding keypair: %v", err), http.StatusInternalServerError)
		return
	}

	resp := GenerateBindingKeypairResponse{
		BindingKeyHandle: bindingUUID.String(),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleGenerateKEMKeypair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req GenerateKEMKeypairRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	bindingPubKey, err := base64.StdEncoding.DecodeString(req.BindingPublicKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid base64 bindingPublicKey: %v", err), http.StatusBadRequest)
		return
	}
	if len(bindingPubKey) == 0 {
		http.Error(w, "bindingPublicKey must not be empty", http.StatusBadRequest)
		return
	}

	kemUUID, err := s.kemGen.GenerateKEMKeypair(bindingPubKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to generate KEM keypair: %v", err), http.StatusInternalServerError)
		return
	}

	resp := GenerateKEMKeypairResponse{
		KEMKeyHandle: kemUUID.String(),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
