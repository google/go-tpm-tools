//go:build cgo

package wskcc

/*
#cgo LDFLAGS: -L${SRCDIR}/../../target/release -lws_key_custody_core
#cgo LDFLAGS: -lcrypto -lssl -lrust_wrapper
#cgo LDFLAGS: -lpthread -ldl -lm -lstdc++
#include "include/ws_key_custody_core.h"
*/
import "C"

import (
	"fmt"
	"unsafe"

	"github.com/google/uuid"
)

// GenerateBindingKeypair generates an X25519 HPKE binding keypair via Rust FFI.
// Returns the UUID key handle of the generated key.
func GenerateBindingKeypair() (uuid.UUID, error) {
	var uuidBytes [16]byte

	algo := C.HpkeAlgorithm{
		kem:  C.KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256,
		kdf:  C.KDF_ALGORITHM_HKDF_SHA256,
		aead: C.AEAD_ALGORITHM_AES_256_GCM,
	}

	rc := C.key_manager_generate_binding_keypair(
		algo,
		C.uint64_t(3600), // 1 hour TTL
		(*C.uint8_t)(unsafe.Pointer(&uuidBytes[0])),
	)
	if rc != 0 {
		return uuid.Nil, fmt.Errorf("key_manager_generate_binding_keypair failed with code %d", rc)
	}

	id, err := uuid.FromBytes(uuidBytes[:])
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid UUID from FFI: %w", err)
	}
	return id, nil
}
