//go:build !cgo || !linux || !amd64

package wskcc

import (
	"fmt"

	"github.com/google/uuid"

	algorithms "github.com/google/go-tpm-tools/keymanager/km_common/proto"
)

// GenerateBindingKeypair is a stub for architectures where the Rust library is not supported.
func GenerateBindingKeypair(_ *algorithms.HpkeAlgorithm, _ uint64) (uuid.UUID, []byte, error) {
	return uuid.Nil, nil, fmt.Errorf("GenerateBindingKeypair is not supported on this architecture")
}

// Open is a stub for architectures where the Rust library is not supported.
func Open(_ uuid.UUID, _, _, _ []byte) ([]byte, error) {
	return nil, fmt.Errorf("Open is not supported on this architecture")
}
