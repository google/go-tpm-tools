//go:build cgo

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
)

// GenerateKEMKeypair generates an X25519 HPKE KEM keypair linked to the
// provided binding public key via Rust FFI.
// Returns the UUID key handle and the KEM public key bytes.
func GenerateKEMKeypair(bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	if len(bindingPubKey) == 0 {
		return uuid.Nil, nil, fmt.Errorf("binding public key must not be empty")
	}

	var uuidBytes [16]byte
	var pubkeyBuf [32]byte
	pubkeyLen := C.size_t(len(pubkeyBuf))

	algo := C.KmHpkeAlgorithm{
		kem:  C.KM_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256,
		kdf:  C.KM_KDF_ALGORITHM_HKDF_SHA256,
		aead: C.KM_AEAD_ALGORITHM_AES_256_GCM,
	}

	rc := C.key_manager_generate_kem_keypair(
		algo,
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

// EnumerateKEMKeys retrieves all active KEM key entries from the Rust KCC registry.
func EnumerateKEMKeys() ([]KEMKeyInfo, error) {
	const maxEntries = 256
	var entries [maxEntries]C.KpsKeyInfo
	var count C.size_t

	rc := C.key_manager_enumerate_kem_keys(
		&entries[0],
		C.size_t(maxEntries),
		&count,
	)
	if rc != 0 {
		return nil, fmt.Errorf("key_manager_enumerate_kem_keys failed with code %d", rc)
	}

	result := make([]KEMKeyInfo, count)
	for i := C.size_t(0); i < count; i++ {
		e := entries[i]

		id, err := uuid.FromBytes(C.GoBytes(unsafe.Pointer(&e.uuid[0]), 16))
		if err != nil {
			return nil, fmt.Errorf("invalid UUID at index %d: %w", i, err)
		}

		kemPubKey := make([]byte, e.kem_pub_key_len)
		copy(kemPubKey, C.GoBytes(unsafe.Pointer(&e.kem_pub_key[0]), C.int(e.kem_pub_key_len)))

		bindingPubKey := make([]byte, e.binding_pub_key_len)
		copy(bindingPubKey, C.GoBytes(unsafe.Pointer(&e.binding_pub_key[0]), C.int(e.binding_pub_key_len)))

		result[i] = KEMKeyInfo{
			ID:                    id,
			KemAlgorithm:          int32(e.algorithm.kem),
			KdfAlgorithm:          int32(e.algorithm.kdf),
			AeadAlgorithm:         int32(e.algorithm.aead),
			KEMPubKey:             kemPubKey,
			BindingPubKey:         bindingPubKey,
			RemainingLifespanSecs: uint64(e.remaining_lifespan_secs),
		}
	}

	return result, nil
}
