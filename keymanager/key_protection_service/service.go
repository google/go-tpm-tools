// Package keyprotectionservice implements the Key Orchestration Layer (KOL)
// for the Key Protection Service. It wraps the KPS Key Custody Core (KCC) FFI
// to provide a Go-native interface for KEM key generation.
package keyprotectionservice

import (
	"github.com/google/uuid"

	keymanager "github.com/google/go-tpm-tools/keymanager/km_common/proto"
)

// KeyProtectionService defines the interface for the underlying Key Custody Core operations.
type KeyProtectionService interface {
	GenerateKEMKeypair(algo *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error)
	GetKemKey(id uuid.UUID) ([]byte, []byte, *keymanager.HpkeAlgorithm, uint64, error)
}

// Service implements KEM keypair operations by delegating to a KeyProtectionService backend.
type Service struct {
	kps KeyProtectionService
}

// NewService creates a new Service with the given KeyProtectionService backend.
func NewService(kps KeyProtectionService) *Service {
	return &Service{kps: kps}
}

// GenerateKEMKeypair generates a KEM keypair linked to the provided binding
// public key by calling the underlying KeyProtectionService backend.
func (s *Service) GenerateKEMKeypair(algo *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	return s.kps.GenerateKEMKeypair(algo, bindingPubKey, lifespanSecs)
}

// GetKemKey retrieves KEM and binding public keys, HpkeAlgorithm and delete_after timestamp
// by calling the underlying KeyProtectionService backend.
func (s *Service) GetKemKey(id uuid.UUID) ([]byte, []byte, *keymanager.HpkeAlgorithm, uint64, error) {
	return s.kps.GetKemKey(id)
}
