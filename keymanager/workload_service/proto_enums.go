package workloadservice

import (
	"fmt"
	"strings"

	keymanager "github.com/google/go-tpm-tools/keymanager/km_common/proto"
)

// Supported algorithms and mechanisms.
var (
	// SupportedKemAlgorithms is the source of truth for supported algorithms.
	SupportedKemAlgorithms = []keymanager.KemAlgorithm{
		keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256,
	}
)

// IsSupportedKemAlgorithm returns true if the KEM algorithm is supported.
func IsSupportedKemAlgorithm(k keymanager.KemAlgorithm) bool {
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

// KemToHpkeAlgorithm returns the full HPKE suite configuration for this algorithm.
func KemToHpkeAlgorithm(k keymanager.KemAlgorithm) (*keymanager.HpkeAlgorithm, error) {
	switch k {
	case keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256:
		return &keymanager.HpkeAlgorithm{
			Kem:  k,
			Kdf:  keymanager.KdfAlgorithm_KDF_ALGORITHM_HKDF_SHA256,
			Aead: keymanager.AeadAlgorithm_AEAD_ALGORITHM_AES_256_GCM,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", k)
	}
}
