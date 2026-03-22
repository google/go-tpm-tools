//go:build cgo && linux && amd64

// Package kpskcc implements the Key Protection Service Key Custody Core interface via Rust FFI.
//
//go:generate cargo build --manifest-path ../../Cargo.toml
package kpskcc

/*
#cgo CFLAGS: -I${SRCDIR}/../../km_common/include
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

const (
	uuidSize      = 16
	kemPubKeySize = 32
	encKeySize    = 32
	sealedCTSize  = 48 // 32-byte secret + 16-byte GCM tag
)

// GenerateKEMKeypair generates an X25519 HPKE KEM keypair linked to the
// provided binding public key via Rust FFI.
// Returns the UUID key handle and the KEM public key bytes.
func GenerateKEMKeypair(algo *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	if len(bindingPubKey) == 0 {
		return uuid.Nil, nil, fmt.Errorf("binding public key must not be empty")
	}

	var uuidBytes [uuidSize]byte
	var pubkeyBuf [kemPubKeySize]byte
	pubkeyLen := C.size_t(len(pubkeyBuf))

	algoBytes, err := proto.Marshal(algo)
	if err != nil {
		return uuid.Nil, nil, fmt.Errorf("failed to marshal HpkeAlgorithm: %v", err)
	}

	if rc := C.key_manager_generate_kem_keypair(
		(*C.uint8_t)(unsafe.Pointer(&algoBytes[0])),
		C.size_t(len(algoBytes)),
		(*C.uint8_t)(unsafe.Pointer(&bindingPubKey[0])),
		C.size_t(len(bindingPubKey)),
		C.uint64_t(lifespanSecs),
		(*C.uint8_t)(unsafe.Pointer(&uuidBytes[0])),
		(*C.uint8_t)(unsafe.Pointer(&pubkeyBuf[0])),
		pubkeyLen,
	); keymanager.Status(rc) != keymanager.Status_STATUS_SUCCESS {
		return uuid.Nil, nil, keymanager.Status(rc).ToStatus()
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
		return nil, false, keymanager.Status(-rc).ToStatus()
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

// DestroyKEMKey destroys the KEM key identified by kemUUID via Rust FFI.
func DestroyKEMKey(kemUUID uuid.UUID) error {
	uuidBytes := kemUUID[:]
	rc := C.key_manager_destroy_kem_key(
		(*C.uint8_t)(unsafe.Pointer(&uuidBytes[0])),
	)
	return keymanager.Status(rc).ToStatus()
}

// GetKEMKey retrieves KEM and binding public keys, HpkeAlgorithm and remaining lifespan via Rust FFI.
func GetKEMKey(id uuid.UUID) ([]byte, []byte, *keymanager.HpkeAlgorithm, uint64, error) {
	var uuidBytes [uuidSize]byte
	copy(uuidBytes[:], id[:])

	var kemPubkeyBuf [kemPubKeySize]byte
	var bindingPubkeyBuf [kemPubKeySize]byte
	var remainingLifespanSecs C.uint64_t
	var algoBuf [C.MAX_ALGORITHM_LEN]byte
	algoLenC := C.size_t(len(algoBuf))

	rc := C.key_manager_get_kem_key(
		(*C.uint8_t)(unsafe.Pointer(&uuidBytes[0])),
		(*C.uint8_t)(unsafe.Pointer(&kemPubkeyBuf[0])),
		C.size_t(len(kemPubkeyBuf)),
		(*C.uint8_t)(unsafe.Pointer(&bindingPubkeyBuf[0])),
		C.size_t(len(bindingPubkeyBuf)),
		(*C.uint8_t)(unsafe.Pointer(&algoBuf[0])),
		&algoLenC,
		&remainingLifespanSecs,
	)
	if keymanager.Status(rc) != keymanager.Status_STATUS_SUCCESS {
		return nil, nil, nil, 0, keymanager.Status(rc).ToStatus()
	}

	kemPubkey := make([]byte, len(kemPubkeyBuf))
	copy(kemPubkey, kemPubkeyBuf[:])
	bindingPubkey := make([]byte, len(bindingPubkeyBuf))
	copy(bindingPubkey, bindingPubkeyBuf[:])
	algo := &keymanager.HpkeAlgorithm{}
	if err := proto.Unmarshal(algoBuf[:algoLenC], algo); err != nil {
		return nil, nil, nil, 0, fmt.Errorf("failed to unmarshal HpkeAlgorithm: %v", err)
	}

	return kemPubkey, bindingPubkey, algo, uint64(remainingLifespanSecs), nil
}

// DecapAndSeal decapsulates a shared secret using the stored KEM key and
// reseals it with the associated binding public key via Rust FFI.
// Returns the new encapsulated key and sealed ciphertext.
func DecapAndSeal(kemUUID uuid.UUID, encapsulatedKey, aad []byte) ([]byte, []byte, error) {
	if len(encapsulatedKey) == 0 {
		return nil, nil, fmt.Errorf("encapsulated key must not be empty")
	}

	uuidBytes := kemUUID[:]

	var outEncKey [encKeySize]byte
	outEncKeyLen := C.size_t(len(outEncKey))
	var outCT [sealedCTSize]byte // 32-byte secret + 16-byte GCM tag
	outCTLen := C.size_t(len(outCT))

	var aadPtr *C.uint8_t
	aadLen := C.size_t(0)
	if len(aad) > 0 {
		aadPtr = (*C.uint8_t)(unsafe.Pointer(&aad[0]))
		aadLen = C.size_t(len(aad))
	}

	if rc := C.key_manager_decap_and_seal(
		(*C.uint8_t)(unsafe.Pointer(&uuidBytes[0])),
		(*C.uint8_t)(unsafe.Pointer(&encapsulatedKey[0])),
		C.size_t(len(encapsulatedKey)),
		aadPtr,
		aadLen,
		(*C.uint8_t)(unsafe.Pointer(&outEncKey[0])),
		outEncKeyLen,
		(*C.uint8_t)(unsafe.Pointer(&outCT[0])),
		outCTLen,
	); keymanager.Status(rc) != keymanager.Status_STATUS_SUCCESS {
		return nil, nil, keymanager.Status(rc).ToStatus()
	}

	sealEnc := make([]byte, outEncKeyLen)
	copy(sealEnc, outEncKey[:outEncKeyLen])
	sealedCT := make([]byte, outCTLen)
	copy(sealedCT, outCT[:outCTLen])
	return sealEnc, sealedCT, nil
}
