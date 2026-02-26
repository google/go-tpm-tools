//go:build cgo

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

	algorithms "github.com/google/go-tpm-tools/keymanager/km_common/proto"
)

// GenerateBindingKeypair generates an X25519 HPKE binding keypair via Rust FFI.
// Returns the UUID key handle and the public key bytes.
func GenerateBindingKeypair(algo *algorithms.HpkeAlgorithm, lifespanSecs uint64) (uuid.UUID, []byte, error) {
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

// DestroyBindingKey destroys the binding key identified by bindingUUID via Rust FFI.
func DestroyBindingKey(bindingUUID uuid.UUID) error {
	uuidBytes := bindingUUID[:]
	rc := C.key_manager_destroy_binding_key(
		(*C.uint8_t)(unsafe.Pointer(&uuidBytes[0])),
	)
	if rc != 0 {
		return fmt.Errorf("key_manager_destroy_binding_key failed with code %d", rc)
	}
	return nil
}
