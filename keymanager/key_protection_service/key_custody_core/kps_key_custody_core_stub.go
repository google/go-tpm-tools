//go:build !cgo || !linux || !amd64

package kpskcc

import (
	"fmt"

	"github.com/google/uuid"

	algorithms "github.com/google/go-tpm-tools/keymanager/km_common/proto"
)

// GenerateKEMKeypair is a stub for architectures where the Rust library is not supported.
func GenerateKEMKeypair(_ *algorithms.HpkeAlgorithm, _ []byte, _ uint64) (uuid.UUID, []byte, error) {
	return uuid.Nil, nil, fmt.Errorf("GenerateKEMKeypair is not supported on this architecture")
}

// EnumerateKEMKeys is a stub for architectures where the Rust library is not supported.
func EnumerateKEMKeys(limit, offset int) ([]KEMKeyInfo, bool, error) {
	return nil, false, fmt.Errorf("EnumerateKEMKeys is not supported on this architecture")
}
