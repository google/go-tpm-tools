package kpskcc

import (
	"errors"

	keymanager "github.com/google/go-tpm-tools/keymanager/km_common/proto"
	"github.com/google/uuid"
)

// ErrKeyNotFound is returned when a key is not found in the KPS core.
var ErrKeyNotFound = errors.New("key not found in KPS")

// KEMKeyInfo holds metadata for a single KEM key returned by EnumerateKEMKeys.
type KEMKeyInfo struct {
	ID                    uuid.UUID
	Algorithm             *keymanager.HpkeAlgorithm
	KEMPubKey             []byte
	RemainingLifespanSecs uint64
}
