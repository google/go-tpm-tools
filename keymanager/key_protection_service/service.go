// Package keyprotectionservice implements the Key Orchestration Layer (KOL)
// for the Key Protection Service. It wraps the KPS Key Custody Core (KCC) FFI
// to provide a Go-native interface for cryptographic operations and key management.
package keyprotectionservice

import (
	kpskcc "github.com/google/go-tpm-tools/keymanager/key_protection_service/key_custody_core"
	"github.com/google/uuid"

	keymanager "github.com/google/go-tpm-tools/keymanager/km_common/proto"
)

// KEMKeyGenerator generates KEM keypairs linked to a binding public key.
type KEMKeyGenerator interface {
	GenerateKEMKeypair(algo *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) ([]byte, []byte, error)
}

// KEMKeyEnumerator enumerates active KEM keys in the KPS registry.
type KEMKeyEnumerator interface {
	EnumerateKEMKeys(limit, offset int) ([]kpskcc.KEMKeyInfo, bool, error)
}

// Service implements KEMKeyGenerator and KEMKeyEnumerator by delegating to the KPS KCC FFI.
type Service struct {
	generateKEMKeypairFn func(algo *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error)
	enumerateKEMKeysFn   func(limit, offset int) ([]kpskcc.KEMKeyInfo, bool, error)
}

// NewService creates a new KPS KOL service with the given KCC functions.
func NewService(
	generateKEMKeypairFn func(algo *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error),
	enumerateKEMKeysFn func(limit, offset int) ([]kpskcc.KEMKeyInfo, bool, error),
) *Service {
	return &Service{
		generateKEMKeypairFn: generateKEMKeypairFn,
		enumerateKEMKeysFn:   enumerateKEMKeysFn,
	}
}

// GenerateKEMKeypair generates a KEM keypair linked to the provided binding
// public key by calling the KPS KCC FFI.
func (s *Service) GenerateKEMKeypair(algo *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	return s.generateKEMKeypairFn(algo, bindingPubKey, lifespanSecs)
}

// EnumerateKEMKeys retrieves all active KEM key entries from the KPS KCC registry.
func (s *Service) EnumerateKEMKeys(limit, offset int) ([]kpskcc.KEMKeyInfo, bool, error) {
	return s.enumerateKEMKeysFn(limit, offset)
}
