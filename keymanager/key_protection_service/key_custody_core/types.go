package kpskcc

import (
	keymanager "github.com/google/go-tpm-tools/keymanager/km_common/proto"
	"github.com/google/uuid"
)

// KEMKeyInfo holds metadata for a single KEM key returned by EnumerateKEMKeys.
type KEMKeyInfo struct {
	ID                    uuid.UUID
	Algorithm             *keymanager.HpkeAlgorithm
	KEMPubKey             []byte
	RemainingLifespanSecs uint64
}
