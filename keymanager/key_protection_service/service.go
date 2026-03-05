// Package keyprotectionservice implements the Key Orchestration Layer (KOL)
// for the Key Protection Service. It wraps the KPS Key Custody Core (KCC) FFI
// to provide a Go-native interface for cryptographic operations and key management.
package keyprotectionservice

import (
	kpskcc "github.com/google/go-tpm-tools/keymanager/key_protection_service/key_custody_core"
	"github.com/google/uuid"

	keymanager "github.com/google/go-tpm-tools/keymanager/km_common/proto"
)

// KeyProtectionService provides the core key custody operations.
type KeyProtectionService interface {
	// GenerateKEMKeypair generates a new Key Encapsulation Mechanism (KEM) keypair.
	// The generated KEM key is linked to the provided binding public key, ensuring that
	// only the holder of the corresponding binding private key can ultimately access
	// the shared secrets.
	//
	// Parameters:
	//   - algo: The HPKE algorithm suite to use for the KEM keypair.
	//   - bindingPubKey: The public key of the workload/client that this KEM key is bound to.
	//   - lifespanSecs: The duration (in seconds) for which the generated keypair remains valid.
	//
	// Returns:
	//   - uuid.UUID: A unique identifier representing the stored KEM keypair.
	//   - []byte: The public KEM key bytes to be shared with the sender.
	//   - error: An error if generation or storage fails.
	GenerateKEMKeypair(algo *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error)

	// DecapAndSeal decapsulates an encapsulated shared secret and reseals it.
	// This operation uses the stored private KEM key to recover the shared secret,
	// and immediately reseals it using the binding public key associated with the KEM key.
	//
	// Parameters:
	//   - kemUUID: The unique identifier of the stored KEM keypair to use for decapsulation.
	//   - encapsulatedKey: The encapsulated shared secret received from a sender.
	//   - aad: Additional Authenticated Data to include in the resealing process.
	//
	// Returns:
	//   - []byte: The encapsulated key for the resealed shared secret (seal_enc).
	//   - []byte: The authenticated ciphertext of the resealed shared secret (sealed_ct).
	//   - error: An error if the KEM key is not found, expired, or if decapsulation/sealing fails.
	DecapAndSeal(kemUUID uuid.UUID, encapsulatedKey, aad []byte) ([]byte, []byte, error)

	// EnumerateKEMKeys retrieves a list of active KEM keys, up to a specified limit
	// and starting from a given offset.
	//
	// Parameters:
	//   - limit: The maximum number of keys to return.
	//   - offset: The index of the first key to return.
	//
	// Returns:
	//   - []kpskcc.KEMKeyInfo: A slice of KEM key information structs.
	//   - bool: True if there are more keys available.
	//   - error: An error if the enumeration fails.
	EnumerateKEMKeys(limit, offset int) ([]kpskcc.KEMKeyInfo, bool, error)

	// DestroyKEMKey removes the specified KEM keypair from the active key registry.
	// This prevents any future decapsulation operations using this key.
	//
	// Parameters:
	//   - kemUUID: The unique identifier of the stored KEM keypair to destroy.
	//
	// Returns:
	//   - error: An error if the key is not found or deletion fails.
	DestroyKEMKey(kemUUID uuid.UUID) error

	// GetKEMKey retrieves metadata and public keys associated with a stored KEM keypair.
	//
	// Parameters:
	//   - id: The unique identifier of the stored KEM keypair.
	//
	// Returns:
	//   - []byte: The public KEM key bytes.
	//   - []byte: The associated binding public key bytes.
	//   - *keymanager.HpkeAlgorithm: The HPKE algorithm suite of the KEM key.
	//   - uint64: The remaining lifespan of the keypair in seconds.
	//   - error: An error if the key is not found or has expired.
	GetKEMKey(id uuid.UUID) ([]byte, []byte, *keymanager.HpkeAlgorithm, uint64, error)
}

// defaultKPS implements KeyProtectionService by delegating to the KPS KCC FFI.
type defaultKPS struct{}

func (d *defaultKPS) GenerateKEMKeypair(algo *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	return kpskcc.GenerateKEMKeypair(algo, bindingPubKey, lifespanSecs)
}

func (d *defaultKPS) DecapAndSeal(kemUUID uuid.UUID, encapsulatedKey, aad []byte) ([]byte, []byte, error) {
	return kpskcc.DecapAndSeal(kemUUID, encapsulatedKey, aad)
}

func (d *defaultKPS) EnumerateKEMKeys(limit, offset int) ([]kpskcc.KEMKeyInfo, bool, error) {
	return kpskcc.EnumerateKEMKeys(limit, offset)
}

func (d *defaultKPS) DestroyKEMKey(kemUUID uuid.UUID) error {
	return kpskcc.DestroyKEMKey(kemUUID)
}

func (d *defaultKPS) GetKEMKey(id uuid.UUID) ([]byte, []byte, *keymanager.HpkeAlgorithm, uint64, error) {
	return kpskcc.GetKEMKey(id)
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

// GenerateKEMKeypair generates a new KEM keypair linked to the provided binding
// public key by delegating to the underlying KeyProtectionService backend.
// It ensures that only the intended workload (holding the binding private key)
// can access the shared secrets sent to the generated KEM public key.
func (s *Service) GenerateKEMKeypair(algo *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	return s.kps.GenerateKEMKeypair(algo, bindingPubKey, lifespanSecs)
}

// DecapAndSeal securely decapsulates an encapsulated shared secret using the
// stored KEM private key and immediately reseals it for the workload using its
// associated binding public key. It delegates cryptographic operations to the
// underlying KeyProtectionService backend.
func (s *Service) DecapAndSeal(kemUUID uuid.UUID, encapsulatedKey, aad []byte) ([]byte, []byte, error) {
	return s.kps.DecapAndSeal(kemUUID, encapsulatedKey, aad)
}

// EnumerateKEMKeys enumerates active KEM keys up to limit by offset calling the underlying KPS.
func (s *Service) EnumerateKEMKeys(limit, offset int) ([]kpskcc.KEMKeyInfo, bool, error) {
	return s.kps.EnumerateKEMKeys(limit, offset)
}

// DestroyKEMKey destroys the KEM key identified by kemUUID by calling the KPS KCC FFI.
// DestroyKEMKey removes the specified KEM keypair from the active key registry
// by delegating to the underlying KeyProtectionService backend.
func (s *Service) DestroyKEMKey(kemUUID uuid.UUID) error {
	return s.kps.DestroyKEMKey(kemUUID)
}

// GetKEMKey retrieves the public KEM key, binding public key, HPKE algorithm,
// and remaining lifespan in seconds of a stored KEM keypair by delegating
// to the underlying KeyProtectionService backend.
func (s *Service) GetKEMKey(id uuid.UUID) ([]byte, []byte, *keymanager.HpkeAlgorithm, uint64, error) {
	return s.kps.GetKEMKey(id)
}
