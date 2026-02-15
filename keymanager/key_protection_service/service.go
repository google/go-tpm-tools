// Package key_protection_service implements the Key Orchestration Layer (KOL)
// for the Key Protection Service. It wraps the KPS Key Custody Core (KCC) FFI
// to provide a Go-native interface for KEM key operations.
package key_protection_service

import "github.com/google/uuid"

// KEMKeyGenerator generates KEM keypairs linked to a binding public key.
type KEMKeyGenerator interface {
	GenerateKEMKeypair(bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error)
}

// DecapSealer decapsulates a shared secret and reseals it with the binding key.
type DecapSealer interface {
	DecapAndSeal(kemUUID uuid.UUID, encapsulatedKey, aad []byte) (sealEnc []byte, sealedCT []byte, err error)
}

// Service implements KEMKeyGenerator and DecapSealer by delegating to the KPS KCC FFI.
type Service struct {
	generateKEMKeypairFn func(bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error)
	decapAndSealFn       func(kemUUID uuid.UUID, encapsulatedKey, aad []byte) ([]byte, []byte, error)
}

// NewService creates a new KPS KOL service with the given KCC functions.
func NewService(
	generateKEMKeypairFn func(bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error),
	decapAndSealFn func(kemUUID uuid.UUID, encapsulatedKey, aad []byte) ([]byte, []byte, error),
) *Service {
	return &Service{
		generateKEMKeypairFn: generateKEMKeypairFn,
		decapAndSealFn:       decapAndSealFn,
	}
}

// GenerateKEMKeypair generates a KEM keypair linked to the provided binding
// public key by calling the KPS KCC FFI.
func (s *Service) GenerateKEMKeypair(bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	return s.generateKEMKeypairFn(bindingPubKey, lifespanSecs)
}

// DecapAndSeal decapsulates a shared secret using the stored KEM key and
// reseals it with the associated binding public key by calling the KPS KCC FFI.
func (s *Service) DecapAndSeal(kemUUID uuid.UUID, encapsulatedKey, aad []byte) ([]byte, []byte, error) {
	return s.decapAndSealFn(kemUUID, encapsulatedKey, aad)
}
