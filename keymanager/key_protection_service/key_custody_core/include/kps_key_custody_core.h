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
// memfd_secret-backed vault, writes the 16-byte UUID key handle to out_uuid,
// and the KEM public key to out_pubkey.
//
// binding_pubkey must be non-null with binding_pubkey_len > 0.
// out_pubkey_len is an in/out param: pass buffer capacity in, receives actual
// key length out. For X25519 keys this is 32 bytes.
//
// Returns 0 on success, -1 on error, -2 if out_pubkey buffer is too small.
int32_t key_manager_generate_kem_keypair(
    KpsHpkeAlgorithm algo,
    const uint8_t *binding_pubkey,
    size_t binding_pubkey_len,
    uint64_t expiry_secs,
    uint8_t *out_uuid,
    uint8_t *out_pubkey,
    size_t *out_pubkey_len);

// key_manager_decap_and_seal decapsulates a shared secret using the stored KEM
// key identified by uuid_bytes, then reseals the shared secret with the
// associated binding public key via HPKE.
//
// uuid_bytes must point to a 16-byte KEM key UUID.
// encapsulated_key is the client-provided encapsulated key.
// aad is optional Additional Authenticated Data (may be NULL if aad_len == 0).
// out_encapsulated_key_len and out_ciphertext_len are in/out params.
//
// Returns 0 on success, -1 on invalid args/key not found, -2 if output buffers
// are too small, -3 if decapsulation fails, -4 if sealing fails.
int32_t key_manager_decap_and_seal(
    const uint8_t *uuid_bytes,
    const uint8_t *encapsulated_key,
    size_t encapsulated_key_len,
    const uint8_t *aad,
    size_t aad_len,
    uint8_t *out_encapsulated_key,
    size_t *out_encapsulated_key_len,
    uint8_t *out_ciphertext,
    size_t *out_ciphertext_len);

// key_manager_destroy_kem_key destroys the KEM key identified by uuid_bytes,
// removing it from the registry and zeroizing its key material.
//
// uuid_bytes must point to a 16-byte KEM key UUID.
//
// Returns 0 on success, -1 if uuid_bytes is null or key was not found.
int32_t key_manager_destroy_kem_key(const uint8_t *uuid_bytes);

#endif // KPS_KEY_CUSTODY_CORE_H_
