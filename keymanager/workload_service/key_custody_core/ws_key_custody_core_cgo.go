//go:build cgo && linux && amd64

// Package wskcc implements the Workload Service Key Custody Core interface via Rust FFI.
package wskcc

/*
#cgo LDFLAGS: -L${SRCDIR}/../../target/release -L${SRCDIR}/../../target/debug -lws_key_custody_core
#cgo LDFLAGS: -lcrypto -lssl
#cgo LDFLAGS: -lpthread -ldl -lm -lstdc++
#include "include/ws_key_custody_core.h"
*/
import "C"

import (
	"fmt"
	"unsafe"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	keymanager "github.com/google/go-tpm-tools/keymanager/km_common/proto"
)

// GenerateBindingKeypair generates an X25519 HPKE binding keypair via Rust FFI.
// Returns the UUID key handle and the public key bytes.
func GenerateBindingKeypair(algo *keymanager.HpkeAlgorithm, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	var uuidBytes [16]byte
	var pubkeyBuf [32]byte
	pubkeyLen := C.size_t(len(pubkeyBuf))

	algoBytes, err := proto.Marshal(algo)
	if err != nil {
		return uuid.Nil, nil, fmt.Errorf("failed to marshal HpkeAlgorithm: %v", err)
	}

	rc := C.key_manager_generate_binding_keypair(
		(*C.uint8_t)(unsafe.Pointer(&algoBytes[0])),
		C.size_t(len(algoBytes)),
		C.uint64_t(lifespanSecs),
		(*C.uint8_t)(unsafe.Pointer(&uuidBytes[0])),
		(*C.uint8_t)(unsafe.Pointer(&pubkeyBuf[0])),
		pubkeyLen,
	)
	if rc != 0 {
		return uuid.Nil, nil, fmt.Errorf("key_manager_generate_binding_keypair failed with code %d", rc)
	}

	id, err := uuid.FromBytes(uuidBytes[:])
	if err != nil {
		return uuid.Nil, nil, fmt.Errorf("invalid UUID from FFI: %w", err)
	}

	pubkey := make([]byte, pubkeyLen)
	copy(pubkey, pubkeyBuf[:pubkeyLen])
	return id, pubkey, nil
}

// GetBindingKey retrieves the binding public key and HpkeAlgorithm via Rust FFI.
func GetBindingKey(id uuid.UUID) ([]byte, *keymanager.HpkeAlgorithm, error) {
	uuidBytes, err := id.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal UUID: %v", err)
	}

	var pubkeyBuf [32]byte
	pubkeyLen := C.size_t(len(pubkeyBuf))
	var algoBuf [C.MAX_ALGORITHM_LEN]byte
	algoLenC := C.size_t(len(algoBuf))

	rc := C.key_manager_get_binding_key(
		(*C.uint8_t)(unsafe.Pointer(&uuidBytes[0])),
		(*C.uint8_t)(unsafe.Pointer(&pubkeyBuf[0])),
		pubkeyLen,
		(*C.uint8_t)(unsafe.Pointer(&algoBuf[0])),
		&algoLenC,
	)
	if rc != 0 {
		return nil, nil, fmt.Errorf("key_manager_get_binding_key failed with code %d", rc)
	}

	pubkey := make([]byte, pubkeyLen)
	copy(pubkey, pubkeyBuf[:pubkeyLen])

	algo := &keymanager.HpkeAlgorithm{}
	if err := proto.Unmarshal(algoBuf[:algoLenC], algo); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal HpkeAlgorithm: %v", err)
	}

	return pubkey, algo, nil
}
