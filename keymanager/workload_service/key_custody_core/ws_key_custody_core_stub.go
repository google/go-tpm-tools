//go:build !cgo || !linux || !amd64

package wskcc

import (
	"fmt"

	"github.com/google/uuid"

	keymanager "github.com/google/go-tpm-tools/keymanager/km_common/proto"
)

// GenerateBindingKeypair is a stub for architectures where the Rust library is not supported.
func GenerateBindingKeypair(_ *keymanager.HpkeAlgorithm, _ uint64) (uuid.UUID, []byte, error) {
	return uuid.Nil, nil, fmt.Errorf("GenerateBindingKeypair is not supported on this architecture")
}

// GetBindingKey is a stub for architectures where the Rust library is not supported.
func GetBindingKey(id uuid.UUID) ([]byte, *keymanager.HpkeAlgorithm, error) {
	return nil, nil, fmt.Errorf("GetBindingKey is not supported on this architecture")
}
