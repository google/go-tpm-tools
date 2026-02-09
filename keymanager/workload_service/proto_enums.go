package workload_service

import (
	"encoding/json"
	"fmt"
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

// KdfAlgorithm represents the requested KDF algorithm.
type KdfAlgorithm int32

const (
	KdfAlgorithmUnspecified KdfAlgorithm = 0
	KdfAlgorithmHKDFSHA384  KdfAlgorithm = 1
)

var (
	kdfAlgorithmToString = map[KdfAlgorithm]string{
		KdfAlgorithmUnspecified: "KDF_ALGORITHM_UNSPECIFIED",
		KdfAlgorithmHKDFSHA384:  "HKDF_SHA384",
	}
	stringToKdfAlgorithm = map[string]KdfAlgorithm{
		"KDF_ALGORITHM_UNSPECIFIED": KdfAlgorithmUnspecified,
		"HKDF_SHA384":               KdfAlgorithmHKDFSHA384,
	}
)

func (k KdfAlgorithm) String() string {
	if s, ok := kdfAlgorithmToString[k]; ok {
		return s
	}
	return fmt.Sprintf("KDF_ALGORITHM_UNKNOWN(%d)", k)
}

func (k KdfAlgorithm) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.String())
}

func (k *KdfAlgorithm) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("KdfAlgorithm must be a string")
	}
	if v, ok := stringToKdfAlgorithm[s]; ok {
		*k = v
		return nil
	}
	return fmt.Errorf("unknown KdfAlgorithm: %q", s)
}

// AeadAlgorithm represents the requested AEAD algorithm.
type AeadAlgorithm int32

const (
	AeadAlgorithmUnspecified AeadAlgorithm = 0
	AeadAlgorithmAES256GCM   AeadAlgorithm = 1
)

var (
	aeadAlgorithmToString = map[AeadAlgorithm]string{
		AeadAlgorithmUnspecified: "AEAD_ALGORITHM_UNSPECIFIED",
		AeadAlgorithmAES256GCM:   "AES_256_GCM",
	}
	stringToAeadAlgorithm = map[string]AeadAlgorithm{
		"AEAD_ALGORITHM_UNSPECIFIED": AeadAlgorithmUnspecified,
		"AES_256_GCM":                AeadAlgorithmAES256GCM,
	}
)

func (k AeadAlgorithm) String() string {
	if s, ok := aeadAlgorithmToString[k]; ok {
		return s
	}
	return fmt.Sprintf("AEAD_ALGORITHM_UNKNOWN(%d)", k)
}

func (k AeadAlgorithm) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.String())
}

func (k *AeadAlgorithm) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("AeadAlgorithm must be a string")
	}
	if v, ok := stringToAeadAlgorithm[s]; ok {
		*k = v
		return nil
	}
	return fmt.Errorf("unknown AeadAlgorithm: %q", s)
}
