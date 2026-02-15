// Package key_protection_service implements the Key Orchestration Layer (KOL)
// for the Key Protection Service. It wraps the KPS Key Custody Core (KCC) FFI
// to provide a Go-native interface for KEM key generation.
package key_protection_service

import "github.com/google/uuid"

// KEMKeyGenerator generates KEM keypairs linked to a binding public key.
type KEMKeyGenerator interface {
	GenerateKEMKeypair(bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error)
}

// Service implements KEMKeyGenerator by delegating to the KPS KCC FFI.
type Service struct {
	generateKEMKeypairFn func(bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error)
}

// NewService creates a new KPS KOL service with the given KCC function.
func NewService(generateKEMKeypairFn func(bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error)) *Service {
	return &Service{generateKEMKeypairFn: generateKEMKeypairFn}
}

// GenerateKEMKeypair generates a KEM keypair linked to the provided binding
// public key by calling the KPS KCC FFI.
func (s *Service) GenerateKEMKeypair(bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	return s.generateKEMKeypairFn(bindingPubKey, lifespanSecs)
}
