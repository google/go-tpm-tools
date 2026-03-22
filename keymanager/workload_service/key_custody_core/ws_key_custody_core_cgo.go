//go:build cgo && linux && amd64

// Package wskcc implements the Workload Service Key Custody Core interface via Rust FFI.
//
//go:generate cargo build --manifest-path ../../Cargo.toml
package wskcc

/*
#cgo CFLAGS: -I${SRCDIR}/../../km_common/include
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

const (
	uuidSize          = 16
	bindingPubKeySize = 32
	sharedSecretSize  = 32
)

// GenerateBindingKeypair generates an X25519 HPKE binding keypair via Rust FFI.
// Returns the UUID key handle and the public key bytes.
func GenerateBindingKeypair(algo *keymanager.HpkeAlgorithm, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	var uuidBytes [uuidSize]byte
	var pubkeyBuf [bindingPubKeySize]byte
	pubkeyLen := C.size_t(len(pubkeyBuf))

	algoBytes, err := proto.Marshal(algo)
	if err != nil {
		return uuid.Nil, nil, fmt.Errorf("failed to marshal HpkeAlgorithm: %v", err)
	}

	if rc := C.key_manager_generate_binding_keypair(
		(*C.uint8_t)(unsafe.Pointer(&algoBytes[0])),
		C.size_t(len(algoBytes)),
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

// DestroyBindingKey destroys the binding key identified by bindingUUID via Rust FFI.
func DestroyBindingKey(bindingUUID uuid.UUID) error {
	uuidBytes := bindingUUID[:]
	rc := C.key_manager_destroy_binding_key(
		(*C.uint8_t)(unsafe.Pointer(&uuidBytes[0])),
	)
	return keymanager.Status(rc).ToStatus()
}

// Open decrypts a sealed ciphertext using the binding key identified by
// bindingUUID via Rust FFI (HPKE Open).
// Returns the decrypted plaintext (shared secret).
func Open(bindingUUID uuid.UUID, enc, ciphertext, aad []byte) ([]byte, error) {
	if len(enc) == 0 {
		return nil, fmt.Errorf("enc must not be empty")
	}
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext must not be empty")
	}

	uuidBytes := bindingUUID[:]

	var outPT [sharedSecretSize]byte
	outPTLen := C.size_t(len(outPT))

	// Rust key_manager_open requires non-null aad pointer.
	// Use a sentinel byte so the pointer is always valid.
	var aadSentinel [1]byte
	aadPtr := (*C.uint8_t)(unsafe.Pointer(&aadSentinel[0]))
	aadLen := C.size_t(0)
	if len(aad) > 0 {
		aadPtr = (*C.uint8_t)(unsafe.Pointer(&aad[0]))
		aadLen = C.size_t(len(aad))
	}

	if rc := C.key_manager_open(
		(*C.uint8_t)(unsafe.Pointer(&uuidBytes[0])),
		(*C.uint8_t)(unsafe.Pointer(&enc[0])),
		C.size_t(len(enc)),
		(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])),
		C.size_t(len(ciphertext)),
		aadPtr,
		aadLen,
		(*C.uint8_t)(unsafe.Pointer(&outPT[0])),
		outPTLen,
	); keymanager.Status(rc) != keymanager.Status_STATUS_SUCCESS {
		return nil, keymanager.Status(rc).ToStatus()
	}

	plaintext := make([]byte, outPTLen)
	copy(plaintext, outPT[:outPTLen])
	return plaintext, nil
}

// GetBindingKey retrieves the binding public key and HpkeAlgorithm via Rust FFI.
func GetBindingKey(id uuid.UUID) ([]byte, *keymanager.HpkeAlgorithm, error) {
	var uuidBytes [uuidSize]byte
	copy(uuidBytes[:], id[:])

	var pubkeyBuf [bindingPubKeySize]byte
	pubkeyLen := C.size_t(len(pubkeyBuf))
	var algoBuf [C.MAX_ALGORITHM_LEN]byte
	algoLenC := C.size_t(len(algoBuf))

	if rc := C.key_manager_get_binding_key(
		(*C.uint8_t)(unsafe.Pointer(&uuidBytes[0])),
		(*C.uint8_t)(unsafe.Pointer(&pubkeyBuf[0])),
		pubkeyLen,
		(*C.uint8_t)(unsafe.Pointer(&algoBuf[0])),
		&algoLenC,
	); keymanager.Status(rc) != keymanager.Status_STATUS_SUCCESS {
		return nil, nil, keymanager.Status(rc).ToStatus()
	}

	pubkey := make([]byte, pubkeyLen)
	copy(pubkey, pubkeyBuf[:pubkeyLen])

	algo := &keymanager.HpkeAlgorithm{}
	if err := proto.Unmarshal(algoBuf[:algoLenC], algo); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal HpkeAlgorithm: %v", err)
	}

	return pubkey, algo, nil
}
