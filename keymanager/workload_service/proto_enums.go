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

// Supported algorithms and mechanisms.
var (
	// SupportedKemAlgorithms is the source of truth for supported algorithms.
	SupportedKemAlgorithms = []KemAlgorithm{
		KemAlgorithmDHKEMX25519HKDFSHA256,
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

// SupportedKemAlgorithmsString returns a comma-separated list of supported KEM algorithms.
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

// KdfAlgorithm represents the requested KDF algorithm.
type KdfAlgorithm int32

const (
	KdfAlgorithmUnspecified KdfAlgorithm = 0
	// Corrected from HKDF_SHA384 to HKDF_SHA256 based on ToHpkeAlgorithm usage which maps to HKDF_SHA256 (val 1)
	KdfAlgorithmHKDFSHA256 KdfAlgorithm = 1
)

var (
	kdfAlgorithmToString = map[KdfAlgorithm]string{
		KdfAlgorithmUnspecified: "KDF_ALGORITHM_UNSPECIFIED",
		KdfAlgorithmHKDFSHA256:  "HKDF_SHA256",
	}
	stringToKdfAlgorithm = map[string]KdfAlgorithm{
		"KDF_ALGORITHM_UNSPECIFIED": KdfAlgorithmUnspecified,
		"HKDF_SHA256":               KdfAlgorithmHKDFSHA256,
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
