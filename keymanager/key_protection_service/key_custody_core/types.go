package kpskcc

import "github.com/google/uuid"

// KEMKeyInfo holds metadata for a single KEM key returned by EnumerateKEMKeys.
type KEMKeyInfo struct {
	ID                    uuid.UUID
	KemAlgorithm          int32
	KdfAlgorithm          int32
	AeadAlgorithm         int32
	KEMPubKey             []byte
	BindingPubKey         []byte
	RemainingLifespanSecs uint64
}
