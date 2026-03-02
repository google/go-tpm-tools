//go:build cgo && linux && amd64

// Package kpskcc implements the Key Protection Service Key Custody Core interface via Rust FFI.
package kpskcc

/*
#cgo LDFLAGS: -L${SRCDIR}/../../target/release -L${SRCDIR}/../../target/debug -lkps_key_custody_core
#cgo LDFLAGS: -lcrypto -lssl
#cgo LDFLAGS: -lpthread -ldl -lm -lstdc++
#include <stdbool.h>
#include "include/kps_key_custody_core.h"
*/
import "C"

import (
	"fmt"
	"unsafe"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	keymanager "github.com/google/go-tpm-tools/keymanager/km_common/proto"
)

// GenerateKEMKeypair generates an X25519 HPKE KEM keypair linked to the
// provided binding public key via Rust FFI.
// Returns the UUID key handle and the KEM public key bytes.
func GenerateKEMKeypair(algo *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	if len(bindingPubKey) == 0 {
		return uuid.Nil, nil, fmt.Errorf("binding public key must not be empty")
	}

	var uuidBytes [16]byte
	var pubkeyBuf [32]byte
	pubkeyLen := C.size_t(len(pubkeyBuf))

	algoBytes, err := proto.Marshal(algo)
	if err != nil {
		return uuid.Nil, nil, fmt.Errorf("failed to marshal HpkeAlgorithm: %v", err)
	}

	rc := C.key_manager_generate_kem_keypair(
		(*C.uint8_t)(unsafe.Pointer(&algoBytes[0])),
		C.size_t(len(algoBytes)),
		(*C.uint8_t)(unsafe.Pointer(&bindingPubKey[0])),
		C.size_t(len(bindingPubKey)),
		C.uint64_t(lifespanSecs),
		(*C.uint8_t)(unsafe.Pointer(&uuidBytes[0])),
		(*C.uint8_t)(unsafe.Pointer(&pubkeyBuf[0])),
		pubkeyLen,
	)
	if rc != 0 {
		return uuid.Nil, nil, fmt.Errorf("key_manager_generate_kem_keypair failed with code %d", rc)
	}

	id, err := uuid.FromBytes(uuidBytes[:])
	if err != nil {
		return uuid.Nil, nil, fmt.Errorf("invalid UUID from FFI: %w", err)
	}

	pubkey := make([]byte, pubkeyLen)
	copy(pubkey, pubkeyBuf[:pubkeyLen])
	return id, pubkey, nil
}

// EnumerateKEMKeys retrieves active KEM key entries from the Rust KCC registry with pagination.
// Returns a list of keys and a boolean indicating if there are more keys to fetch.
func EnumerateKEMKeys(limit, offset int) ([]KEMKeyInfo, bool, error) {
	if limit <= 0 {
		return nil, false, fmt.Errorf("limit must be positive")
	}
	if offset < 0 {
		return nil, false, fmt.Errorf("offset must be non-negative")
	}

	entries := make([]C.KpsKeyInfo, limit)
	var hasMore C.bool

	rc := C.key_manager_enumerate_kem_keys(
		&entries[0],
		C.size_t(limit),
		C.size_t(offset),
		&hasMore,
	)
	if rc < 0 {
		return nil, false, fmt.Errorf("key_manager_enumerate_kem_keys failed with code %d", rc)
	}

	count := int(rc)
	result := make([]KEMKeyInfo, count)
	for i, e := range entries[:count] {
		id, err := uuid.FromBytes(C.GoBytes(unsafe.Pointer(&e.uuid[0]), 16))
		if err != nil {
			return nil, false, fmt.Errorf("invalid UUID at index %d: %w", i, err)
		}

		kemPubKey := C.GoBytes(unsafe.Pointer(&e.pub_key[0]), C.int(e.pub_key_len))

		algoBytes := C.GoBytes(unsafe.Pointer(&e.algorithm[0]), C.int(e.algorithm_len))
		algo := &keymanager.HpkeAlgorithm{}
		if err := proto.Unmarshal(algoBytes, algo); err != nil {
			return nil, false, fmt.Errorf("failed to unmarshal algorithm for key %d: %w", i, err)
		}

		result[i] = KEMKeyInfo{
			ID:                    id,
			Algorithm:             algo,
			KEMPubKey:             kemPubKey,
			RemainingLifespanSecs: uint64(e.remaining_lifespan_secs),
		}
	}

	return result, bool(hasMore), nil
}
