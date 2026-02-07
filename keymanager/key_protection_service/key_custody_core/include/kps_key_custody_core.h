#ifndef KPS_KEY_CUSTODY_CORE_H_
#define KPS_KEY_CUSTODY_CORE_H_

#include <stdint.h>
#include <stddef.h>

// HpkeAlgorithm matches the #[repr(C)] Rust struct generated from algorithms.proto.
typedef struct {
    int32_t kem;
    int32_t kdf;
    int32_t aead;
} KpsHpkeAlgorithm;

// Algorithm constants matching algorithms.proto enum values.
#define KPS_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256 1
#define KPS_KDF_ALGORITHM_HKDF_SHA256 1
#define KPS_AEAD_ALGORITHM_AES_256_GCM 1

// key_manager_generate_kem_keypair generates an X25519 HPKE KEM keypair linked
// to the provided binding public key. Stores the private key in a
// memfd_secret-backed vault and writes the 16-byte UUID key handle to out_uuid.
//
// binding_pubkey must be non-null with binding_pubkey_len > 0.
// Returns 0 on success, non-zero on error.
int32_t key_manager_generate_kem_keypair(
    KpsHpkeAlgorithm algo,
    const uint8_t *binding_pubkey,
    size_t binding_pubkey_len,
    uint64_t expiry_secs,
    uint8_t *out_uuid);

#endif // KPS_KEY_CUSTODY_CORE_H_
