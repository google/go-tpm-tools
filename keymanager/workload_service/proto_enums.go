package workload_service

import (
	"encoding/json"
	"fmt"
	"strings"

	algorithms "github.com/google/go-tpm-tools/keymanager/km_common/proto"
)

// These enum values mirror the proto definitions in PROTOS.md and are used by
// the WSD JSON API contract.

// KemAlgorithm represents the requested KEM algorithm.
type KemAlgorithm int32

const (
	KemAlgorithmUnspecified           KemAlgorithm = 0
	KemAlgorithmDHKEMX25519HKDFSHA256 KemAlgorithm = 1
)

var (
	kemAlgorithmToString = map[KemAlgorithm]string{
		KemAlgorithmUnspecified:           "KEM_ALGORITHM_UNSPECIFIED",
		KemAlgorithmDHKEMX25519HKDFSHA256: "DHKEM_X25519_HKDF_SHA256",
	}
	stringToKemAlgorithm = map[string]KemAlgorithm{
		"KEM_ALGORITHM_UNSPECIFIED": KemAlgorithmUnspecified,
		"DHKEM_X25519_HKDF_SHA256":  KemAlgorithmDHKEMX25519HKDFSHA256,
	}
)

func (k KemAlgorithm) String() string {
	if s, ok := kemAlgorithmToString[k]; ok {
		return s
	}
	return fmt.Sprintf("KEM_ALGORITHM_UNKNOWN(%d)", k)
}

func (k KemAlgorithm) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.String())
}

func (k *KemAlgorithm) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("KemAlgorithm must be a string")
	}
	if v, ok := stringToKemAlgorithm[s]; ok {
		*k = v
		return nil
	}
	return fmt.Errorf("unknown KemAlgorithm: %q", s)
}

// KeyProtectionMechanism represents the requested key protection backend.
type KeyProtectionMechanism int32

const (
	KeyProtectionMechanismDefault KeyProtectionMechanism = 1
	KeyProtectionMechanismVM      KeyProtectionMechanism = 2
)

var (
	keyProtectionMechanismToString = map[KeyProtectionMechanism]string{
		KeyProtectionMechanismDefault: "KEY_PROTECTION_DEFAULT",
		KeyProtectionMechanismVM:      "KEY_PROTECTION_VM",
	}
	stringToKeyProtectionMechanism = map[string]KeyProtectionMechanism{
		"KEY_PROTECTION_DEFAULT": KeyProtectionMechanismDefault,
		"KEY_PROTECTION_VM":      KeyProtectionMechanismVM,
	}
)

func (k KeyProtectionMechanism) String() string {
	if s, ok := keyProtectionMechanismToString[k]; ok {
		return s
	}
	return fmt.Sprintf("KEY_PROTECTION_MECHANISM_UNKNOWN(%d)", k)
}

func (k KeyProtectionMechanism) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.String())
}

func (k *KeyProtectionMechanism) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("KeyProtectionMechanism must be a string")
	}
	if v, ok := stringToKeyProtectionMechanism[s]; ok {
		*k = v
		return nil
	}
	return fmt.Errorf("unknown KeyProtectionMechanism: %q", s)
}

// Supported algorithms and mechanisms.
var (
	// SupportedKemAlgorithms is the source of truth for supported algorithms.
	SupportedKemAlgorithms = []KemAlgorithm{
		KemAlgorithmDHKEMX25519HKDFSHA256,
	}

	// SupportedKeyProtectionMechanisms is the source of truth for supported mechanisms.
	SupportedKeyProtectionMechanisms = []KeyProtectionMechanism{
		KeyProtectionMechanismVM,
	}
)

// IsSupported returns true if the KEM algorithm is supported.
func (k KemAlgorithm) IsSupported() bool {
	for _, supported := range SupportedKemAlgorithms {
		if k == supported {
			return true
		}
	}
	return false
}

// IsSupported returns true if the key protection mechanism is supported.
func (k KeyProtectionMechanism) IsSupported() bool {
	for _, supported := range SupportedKeyProtectionMechanisms {
		if k == supported {
			return true
		}
	}
	return false
}

// SupportedKemAlgorithmsString returns a comma-separated list of supported KEM algorithms.
func SupportedKemAlgorithmsString() string {
	var names []string
	for _, k := range SupportedKemAlgorithms {
		names = append(names, k.String())
	}
	return strings.Join(names, ", ")
}

// ToHpkeAlgorithm returns the full HPKE suite configuration for this algorithm.
func (k KemAlgorithm) ToHpkeAlgorithm() (*algorithms.HpkeAlgorithm, error) {
	switch k {
	case KemAlgorithmDHKEMX25519HKDFSHA256:
		return &algorithms.HpkeAlgorithm{
			Kem:  algorithms.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256,
			Kdf:  algorithms.KdfAlgorithm_KDF_ALGORITHM_HKDF_SHA256,
			Aead: algorithms.AeadAlgorithm_AEAD_ALGORITHM_AES_256_GCM,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", k)
	}
}
