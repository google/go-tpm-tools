package workloadservice

import (
	"encoding/json"
	"fmt"
	"strings"

	keymanager "github.com/google/go-tpm-tools/keymanager/km_common/proto"
)

// These enum values mirror the proto definitions in PROTOS.md and are used by
// the WSD JSON API contract.

// KemAlgorithm represents the requested KEM algorithm.
type KemAlgorithm int32

const (
	// KemAlgorithmUnspecified indicates an unspecified or invalid KEM algorithm.
	KemAlgorithmUnspecified KemAlgorithm = 0
	// KemAlgorithmDHKEMX25519HKDFSHA256 specifies the DHKEM(X25519, HKDF-SHA256) algorithm.
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

// MarshalJSON converts a KemAlgorithm enum value to its JSON string representation.
func (k KemAlgorithm) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.String())
}

// UnmarshalJSON converts a JSON string back into a KemAlgorithm enum value.
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
	KeyProtectionMechanismUnspecified KeyProtectionMechanism = 0
	// KeyProtectionMechanismDefault is the default but invalid value.
	KeyProtectionMechanismDefault KeyProtectionMechanism = 1
	// KeyProtectionMechanismVM specifies that the key is protected by the VM.
	KeyProtectionMechanismVM         KeyProtectionMechanism = 2
	KeyProtectionMechanismVMEmulated KeyProtectionMechanism = 3
)

var (
	keyProtectionMechanismToString = map[KeyProtectionMechanism]string{
		KeyProtectionMechanismUnspecified: "KEY_PROTECTION_UNSPECIFIED",
		KeyProtectionMechanismDefault:     "DEFAULT",
		KeyProtectionMechanismVM:          "KEY_PROTECTION_VM",
		KeyProtectionMechanismVMEmulated:  "KEY_PROTECTION_VM_EMULATED",
	}
	stringToKeyProtectionMechanism = map[string]KeyProtectionMechanism{
		"KEY_PROTECTION_UNSPECIFIED": KeyProtectionMechanismUnspecified,
		"DEFAULT":                    KeyProtectionMechanismDefault,
		"KEY_PROTECTION_VM":          KeyProtectionMechanismVM,
		"KEY_PROTECTION_VM_EMULATED": KeyProtectionMechanismVMEmulated,
	}
)

func (k KeyProtectionMechanism) String() string {
	if s, ok := keyProtectionMechanismToString[k]; ok {
		return s
	}
	return fmt.Sprintf("KEY_PROTECTION_MECHANISM_UNKNOWN(%d)", k)
}

// MarshalJSON converts a KeyProtectionMechanism enum value to its JSON string representation.
func (k KeyProtectionMechanism) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.String())
}

// UnmarshalJSON parses a JSON string into a KeyProtectionMechanism enum value.
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
		KeyProtectionMechanismVMEmulated,
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

// SupportedKemAlgorithmsString returns a comma-separated list of supported KEM keymanager.
func SupportedKemAlgorithmsString() string {
	var names []string
	for _, k := range SupportedKemAlgorithms {
		names = append(names, k.String())
	}
	return strings.Join(names, ", ")
}

// ToHpkeAlgorithm returns the full HPKE suite configuration for this algorithm.
func (k KemAlgorithm) ToHpkeAlgorithm() (*keymanager.HpkeAlgorithm, error) {
	switch k {
	case KemAlgorithmDHKEMX25519HKDFSHA256:
		return &keymanager.HpkeAlgorithm{
			Kem:  keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256,
			Kdf:  keymanager.KdfAlgorithm_KDF_ALGORITHM_HKDF_SHA256,
			Aead: keymanager.AeadAlgorithm_AEAD_ALGORITHM_AES_256_GCM,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", k)
	}
}
