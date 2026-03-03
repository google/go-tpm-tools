// Package keyprotectionservice implements the Key Orchestration Layer (KOL)
// for the Key Protection Service. It wraps the KPS Key Custody Core (KCC) FFI
// to provide a Go-native interface for KEM key operations.
package keyprotectionservice

import (
	"github.com/google/uuid"

	kpscc "github.com/google/go-tpm-tools/keymanager/key_protection_service/key_custody_core"
	keymanager "github.com/google/go-tpm-tools/keymanager/km_common/proto"
)

// KeyProtectionService provides the core key custody operations.
type KeyProtectionService interface {
	GenerateKEMKeypair(algo *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error)
	DecapAndSeal(kemUUID uuid.UUID, encapsulatedKey, aad []byte) ([]byte, []byte, error)
}

// defaultKPS implements KeyProtectionService by delegating to the KPS KCC FFI.
type defaultKPS struct{}

func (d *defaultKPS) GenerateKEMKeypair(algo *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	return kpscc.GenerateKEMKeypair(algo, bindingPubKey, lifespanSecs)
}

func (d *defaultKPS) DecapAndSeal(kemUUID uuid.UUID, encapsulatedKey, aad []byte) ([]byte, []byte, error) {
	return kpscc.DecapAndSeal(kemUUID, encapsulatedKey, aad)
}

// Service implements KeyProtectionService by delegating to an underlying KeyProtectionService.
type Service struct {
	kps KeyProtectionService
}

// NewService creates a new KPS KOL service using the default KPS.
func NewService() *Service {
	return &Service{
		kps: &defaultKPS{},
	}
}

// newServiceWithKPS creates a new KPS KOL service using the provided KPS for testing.
func newServiceWithKPS(kps KeyProtectionService) *Service {
	return &Service{
		kps: kps,
	}
}

// GenerateKEMKeypair generates a KEM keypair linked to the provided binding
// public key by calling the underlying KPS.
func (s *Service) GenerateKEMKeypair(algo *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	return s.kps.GenerateKEMKeypair(algo, bindingPubKey, lifespanSecs)
}

// DecapAndSeal decapsulates a shared secret using the stored KEM key and
// reseals it with the associated binding public key by calling the underlying KPS.
func (s *Service) DecapAndSeal(kemUUID uuid.UUID, encapsulatedKey, aad []byte) ([]byte, []byte, error) {
	return s.kps.DecapAndSeal(kemUUID, encapsulatedKey, aad)
}
