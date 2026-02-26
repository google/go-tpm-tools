// Package keyprotectionservice implements the Key Orchestration Layer (KOL)
// for the Key Protection Service. It wraps the KPS Key Custody Core (KCC) FFI
// to provide a Go-native interface for KEM key generation.
package keyprotectionservice

import (
	"github.com/google/uuid"

	algorithms "github.com/google/go-tpm-tools/keymanager/km_common/proto"
)

// KEMKeyGenerator generates KEM keypairs linked to a binding public key.

// KEMKeyDestroyer destroys a KEM key by UUID.
type KEMKeyDestroyer interface {
	DestroyKEMKey(kemUUID uuid.UUID) error
}

type KEMKeyGenerator interface {
	GenerateKEMKeypair(algo *algorithms.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error)
}

// Service implements KEMKeyGenerator and KEMKeyDestroyer by
// delegating to the KPS KCC FFI.
type Service struct {
	destroyKEMKeyFn      func(kemUUID uuid.UUID) error
	generateKEMKeypairFn func(algo *algorithms.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error)
}

// NewService creates a new KPS KOL service with the given KCC function.
func NewService(
	generateKEMKeypairFn func(algo *algorithms.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error),
	destroyKEMKeyFn func(kemUUID uuid.UUID) error,
) *Service {
	return &Service{
		generateKEMKeypairFn: generateKEMKeypairFn,
		destroyKEMKeyFn:      destroyKEMKeyFn,
	}
}

// GenerateKEMKeypair generates a KEM keypair linked to the provided binding
// public key by calling the KPS KCC FFI.
func (s *Service) GenerateKEMKeypair(algo *algorithms.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	return s.generateKEMKeypairFn(algo, bindingPubKey, lifespanSecs)
}

// DestroyKEMKey destroys the KEM key identified by kemUUID by calling the KPS KCC FFI.
func (s *Service) DestroyKEMKey(kemUUID uuid.UUID) error {
	return s.destroyKEMKeyFn(kemUUID)
}
