//go:build cgo && linux && amd64

// Package kpskcc implements the Key Protection Service Key Custody Core interface via Rust FFI.
package kpskcc

/*
#cgo LDFLAGS: -L${SRCDIR}/../../target/release -L${SRCDIR}/../../target/debug -lkps_key_custody_core
#cgo LDFLAGS: -lcrypto -lssl
#cgo LDFLAGS: -lpthread -ldl -lm -lstdc++
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

// GetKemKey retrieves KEM and binding public keys and delete_after timestamp via Rust FFI.
func GetKemKey(id uuid.UUID) ([]byte, []byte, uint64, error) {
	var uuidBytes [16]byte
	copy(uuidBytes[:], id[:])

	var kemPubkeyBuf [32]byte
	var bindingPubkeyBuf [32]byte
	var deleteAfter C.uint64_t

	rc := C.key_manager_get_kem_key(
		(*C.uint8_t)(unsafe.Pointer(&uuidBytes[0])),
		(*C.uint8_t)(unsafe.Pointer(&kemPubkeyBuf[0])),
		C.size_t(len(kemPubkeyBuf)),
		(*C.uint8_t)(unsafe.Pointer(&bindingPubkeyBuf[0])),
		C.size_t(len(bindingPubkeyBuf)),
		&deleteAfter,
	)
	if rc != 0 {
		return nil, nil, 0, fmt.Errorf("key_manager_get_kem_key failed with code %d", rc)
	}

	kemPubkey := make([]byte, len(kemPubkeyBuf))
	copy(kemPubkey, kemPubkeyBuf[:])
	bindingPubkey := make([]byte, len(bindingPubkeyBuf))
	copy(bindingPubkey, bindingPubkeyBuf[:])

	return kemPubkey, bindingPubkey, uint64(deleteAfter), nil
}
