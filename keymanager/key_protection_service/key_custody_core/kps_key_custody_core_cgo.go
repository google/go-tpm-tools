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

// DecapAndSeal decapsulates a shared secret using the stored KEM key and
// reseals it with the associated binding public key via Rust FFI.
// Returns the new encapsulated key and sealed ciphertext.
func DecapAndSeal(kemUUID uuid.UUID, encapsulatedKey, aad []byte) ([]byte, []byte, error) {
	if len(encapsulatedKey) == 0 {
		return nil, nil, fmt.Errorf("encapsulated key must not be empty")
	}

	uuidBytes := kemUUID[:]

	var outEncKey [32]byte
	outEncKeyLen := C.size_t(len(outEncKey))
	var outCT [48]byte // 32-byte secret + 16-byte GCM tag
	outCTLen := C.size_t(len(outCT))

	var aadPtr *C.uint8_t
	aadLen := C.size_t(0)
	if len(aad) > 0 {
		aadPtr = (*C.uint8_t)(unsafe.Pointer(&aad[0]))
		aadLen = C.size_t(len(aad))
	}

	rc := C.key_manager_decap_and_seal(
		(*C.uint8_t)(unsafe.Pointer(&uuidBytes[0])),
		(*C.uint8_t)(unsafe.Pointer(&encapsulatedKey[0])),
		C.size_t(len(encapsulatedKey)),
		aadPtr,
		aadLen,
		(*C.uint8_t)(unsafe.Pointer(&outEncKey[0])),
		&outEncKeyLen,
		(*C.uint8_t)(unsafe.Pointer(&outCT[0])),
		&outCTLen,
	)
	if rc != 0 {
		return nil, nil, fmt.Errorf("key_manager_decap_and_seal failed with code %d", rc)
	}

	sealEnc := make([]byte, outEncKeyLen)
	copy(sealEnc, outEncKey[:outEncKeyLen])
	sealedCT := make([]byte, outCTLen)
	copy(sealedCT, outCT[:outCTLen])
	return sealEnc, sealedCT, nil
}
