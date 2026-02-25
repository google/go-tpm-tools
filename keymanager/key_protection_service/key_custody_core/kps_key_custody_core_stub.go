//go:build !cgo || (!amd64 && !arm64)

package kpskcc

import (
	"fmt"

	"github.com/google/uuid"

	algorithms "github.com/google/go-tpm-tools/keymanager/km_common/proto"
)

// GenerateKEMKeypair is a stub for architectures where the Rust library is not supported.
func GenerateKEMKeypair(algo *algorithms.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	return uuid.Nil, nil, fmt.Errorf("GenerateKEMKeypair is not supported on this architecture")
}
