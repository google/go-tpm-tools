#ifndef WS_KEY_CUSTODY_CORE_H_
#define WS_KEY_CUSTODY_CORE_H_

#include <stdint.h>
#include <stddef.h>

// HpkeAlgorithm matches the #[repr(C)] Rust struct generated from algorithms.proto.
typedef struct {
    int32_t kem;
    int32_t kdf;
    int32_t aead;
} HpkeAlgorithm;

// Algorithm constants matching algorithms.proto enum values.
#define KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256 1
#define KDF_ALGORITHM_HKDF_SHA256 1
#define AEAD_ALGORITHM_AES_256_GCM 1

// key_manager_generate_binding_keypair generates an X25519 HPKE binding keypair,
// stores the private key in a memfd_secret-backed vault, and writes the 16-byte
// UUID key handle to out_uuid.
//
// Returns 0 on success, non-zero on error.
int32_t key_manager_generate_binding_keypair(
    HpkeAlgorithm algo,
    uint64_t expiry_secs,
    uint8_t *out_uuid);

#endif // WS_KEY_CUSTODY_CORE_H_
