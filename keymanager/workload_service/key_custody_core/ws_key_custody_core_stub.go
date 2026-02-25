//go:build !cgo || (!amd64 && !arm64)

package wskcc

import (
	"fmt"

	"github.com/google/uuid"

	algorithms "github.com/google/go-tpm-tools/keymanager/km_common/proto"
)

// GenerateBindingKeypair is a stub for architectures where the Rust library is not supported.
func GenerateBindingKeypair(algo *algorithms.HpkeAlgorithm, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	return uuid.Nil, nil, fmt.Errorf("GenerateBindingKeypair is not supported on this architecture")
}
