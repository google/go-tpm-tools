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

	var outPT [32]byte
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

	rc := C.key_manager_open(
		(*C.uint8_t)(unsafe.Pointer(&uuidBytes[0])),
		(*C.uint8_t)(unsafe.Pointer(&enc[0])),
		C.size_t(len(enc)),
		(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])),
		C.size_t(len(ciphertext)),
		aadPtr,
		aadLen,
		(*C.uint8_t)(unsafe.Pointer(&outPT[0])),
		outPTLen,
	)
	if rc != 0 {
		return nil, fmt.Errorf("key_manager_open failed with code %d", rc)
	}

	plaintext := make([]byte, outPTLen)
	copy(plaintext, outPT[:outPTLen])
	return plaintext, nil
}
