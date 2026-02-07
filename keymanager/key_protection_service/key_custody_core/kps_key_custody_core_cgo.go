//go:build cgo

package kpskcc

/*
#cgo LDFLAGS: -L${SRCDIR}/../../target/release -lkps_key_custody_core
#cgo LDFLAGS: -lcrypto -lssl -lrust_wrapper
#cgo LDFLAGS: -lpthread -ldl -lm -lstdc++
#include "include/kps_key_custody_core.h"
*/
import "C"

import (
	"fmt"
	"unsafe"

	"github.com/google/uuid"
)

// GenerateKEMKeypair generates an X25519 HPKE KEM keypair linked to the
// provided binding public key via Rust FFI.
// Returns the UUID key handle of the generated KEM key.
func GenerateKEMKeypair(bindingPubKey []byte) (uuid.UUID, error) {
	if len(bindingPubKey) == 0 {
		return uuid.Nil, fmt.Errorf("binding public key must not be empty")
	}

	var uuidBytes [16]byte

	algo := C.KpsHpkeAlgorithm{
		kem:  C.KPS_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256,
		kdf:  C.KPS_KDF_ALGORITHM_HKDF_SHA256,
		aead: C.KPS_AEAD_ALGORITHM_AES_256_GCM,
	}

	rc := C.key_manager_generate_kem_keypair(
		algo,
		(*C.uint8_t)(unsafe.Pointer(&bindingPubKey[0])),
		C.size_t(len(bindingPubKey)),
		C.uint64_t(3600), // 1 hour TTL
		(*C.uint8_t)(unsafe.Pointer(&uuidBytes[0])),
	)
	if rc != 0 {
		return uuid.Nil, fmt.Errorf("key_manager_generate_kem_keypair failed with code %d", rc)
	}

	id, err := uuid.FromBytes(uuidBytes[:])
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid UUID from FFI: %w", err)
	}
	return id, nil
}
