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
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/durationpb"

	kpscc "github.com/google/go-tpm-tools/keymanager/key_protection_service/key_custody_core"
	keymanager "github.com/google/go-tpm-tools/keymanager/km_common/proto"
	wskcc "github.com/google/go-tpm-tools/keymanager/workload_service/key_custody_core"
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

// GenerateKeyRequest is the JSON body for POST /v1/keys:generate_key.
type GenerateKeyRequest struct {
	Algorithm AlgorithmDetails `json:"algorithm"`
	Lifespan  uint64           `json:"lifespan"`
}

// DestroyRequest is the JSON body for POST /v1/keys:destroy.
type DestroyRequest struct {
	KeyHandle KeyHandle `json:"key_handle"`
}

// GenerateKeyResponse is returned by POST /v1/keys:generate_key.
type GenerateKeyResponse struct {
	KeyHandle              KeyHandle  `json:"key_handle"`
	PubKey                 PubKeyInfo `json:"pub_key"`
	KeyProtectionMechanism string     `json:"key_protection_mechanism"`
	ExpirationTime         int64      `json:"expiration_time"`
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
	KeyHandle              KeyHandle  `json:"key_handle"`
	PubKey                 PubKeyInfo `json:"pub_key"`
	KeyProtectionMechanism string     `json:"key_protection_mechanism"`
	ExpirationTime         int64      `json:"expiration_time"`
}

// PubKeyInfo contains the public key and its algorithm.
type PubKeyInfo struct {
	Algorithm AlgorithmDetails `json:"algorithm"`
	PublicKey string           `json:"public_key"` // Base64 encoded public key
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

	claimsChan chan *ClaimsCall

	httpServer *http.Server
	listener   net.Listener
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
		claimsChan:           make(chan *ClaimsCall, 4),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/keys:generate_key", s.handleGenerateKey)
	mux.HandleFunc("POST /v1/keys:decap", s.handleDecaps)
	mux.HandleFunc("GET /v1/capabilities", s.handleGetCapabilities)
	mux.HandleFunc("GET /v1/keys", s.handleEnumerateKeys)
	mux.HandleFunc("POST /v1/keys:destroy", s.handleDestroy)
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

	// Validate lifespan is positive and does not cause int64 overflow.
	if req.Lifespan == 0 {
		writeError(w, "lifespan must be greater than 0s", http.StatusBadRequest)
		return
	}
	if req.Lifespan > math.MaxInt64 {
		writeError(w, "lifespan exceeds maximum allowed value", http.StatusBadRequest)
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
	bindingUUID, bindingPubKey, err := s.workloadService.GenerateBindingKeypair(algo, req.Lifespan)
	if err != nil {
		writeError(w, fmt.Sprintf("failed to generate binding keypair: %v", err), http.StatusInternalServerError)
		return
	}

	// Generate KEM keypair via KPS KOL, passing the binding public key.
	kemUUID, kemPubKey, err := s.keyProtectionService.GenerateKEMKeypair(algo, bindingPubKey, req.Lifespan)
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
		PubKey: PubKeyInfo{
			Algorithm: AlgorithmDetails{
				Type: "kem",
				Params: AlgorithmParams{
					KemID: req.Algorithm.Params.KemID,
				},
			},
			PublicKey: base64.StdEncoding.EncodeToString(kemPubKey),
		},
		KeyProtectionMechanism: keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM_EMULATED.String(),
		ExpirationTime:         time.Now().Unix() + int64(req.Lifespan),
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

func (s *Server) handleEnumerateKeys(w http.ResponseWriter, _ *http.Request) {
	keys, _, err := s.keyProtectionService.EnumerateKEMKeys(100, 0)
	if err != nil {
		writeError(w, fmt.Sprintf("failed to enumerate keys: %v", err), http.StatusInternalServerError)
		return
	}

	keyInfos := make([]KeyInfo, 0, len(keys))
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
			KeyProtectionMechanism: keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM_EMULATED.String(),
			ExpirationTime:         time.Now().Unix() + int64(key.RemainingLifespanSecs),
		})
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
