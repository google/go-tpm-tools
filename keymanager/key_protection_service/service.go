// Package key_protection_service implements the Key Orchestration Layer (KOL)
// for the Key Protection Service. It wraps the KPS Key Custody Core (KCC) FFI
// to provide a Go-native interface for KEM key generation and enumeration.
package key_protection_service

import (
	kpskcc "github.com/google/go-tpm-tools/keymanager/key_protection_service/key_custody_core"
	"github.com/google/uuid"
)

// KEMKeyGenerator generates KEM keypairs linked to a binding public key.
type KEMKeyGenerator interface {
	GenerateKEMKeypair(bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error)
}

// KEMKeyEnumerator enumerates active KEM keys in the KPS registry.
type KEMKeyEnumerator interface {
	EnumerateKEMKeys() ([]kpskcc.KEMKeyInfo, error)
}

// Service implements KEMKeyGenerator and KEMKeyEnumerator by delegating to the KPS KCC FFI.
type Service struct {
	generateKEMKeypairFn func(bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error)
	enumerateKEMKeysFn   func() ([]kpskcc.KEMKeyInfo, error)
}

// NewService creates a new KPS KOL service with the given KCC functions.
func NewService(
	generateKEMKeypairFn func(bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error),
	enumerateKEMKeysFn func() ([]kpskcc.KEMKeyInfo, error),
) *Service {
	return &Service{
		generateKEMKeypairFn: generateKEMKeypairFn,
		enumerateKEMKeysFn:   enumerateKEMKeysFn,
	}
}

// GenerateKEMKeypair generates a KEM keypair linked to the provided binding
// public key by calling the KPS KCC FFI.
func (s *Service) GenerateKEMKeypair(bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	return s.generateKEMKeypairFn(bindingPubKey, lifespanSecs)
}

// EnumerateKEMKeys retrieves all active KEM key entries from the KPS KCC registry.
func (s *Service) EnumerateKEMKeys() ([]kpskcc.KEMKeyInfo, error) {
	return s.enumerateKEMKeysFn()
}
