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
// stores the private key in a memfd_secret-backed vault, writes the 16-byte
// UUID key handle to out_uuid, and the public key to out_pubkey.
//
// out_pubkey_len is an in/out param: pass buffer capacity in, receives actual
// key length out. For X25519 keys this is 32 bytes.
//
// Returns 0 on success, -1 on key generation error, -2 if out_pubkey buffer
// is too small.
int32_t key_manager_generate_binding_keypair(
    HpkeAlgorithm algo,
    uint64_t expiry_secs,
    uint8_t *out_uuid,
    uint8_t *out_pubkey,
    size_t *out_pubkey_len);

// key_manager_open decrypts a ciphertext using the binding key identified by
// uuid_bytes via HPKE Open.
//
// uuid_bytes must point to a 16-byte binding key UUID.
// enc is the encapsulated shared secret from the seal operation.
// ciphertext is the sealed ciphertext to decrypt.
// aad is the Additional Authenticated Data (must not be NULL; pass empty data
// with aad_len == 0 if unused).
// out_plaintext_len is an in/out param: pass buffer capacity in, receives
// actual plaintext length out.
//
// Returns 0 on success, -1 on invalid args/key not found, -2 if out_plaintext
// buffer is too small, -3 if decryption fails.
int32_t key_manager_open(
    const uint8_t *uuid_bytes,
    const uint8_t *enc,
    size_t enc_len,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *aad,
    size_t aad_len,
    uint8_t *out_plaintext,
    size_t *out_plaintext_len);

// key_manager_destroy_binding_key destroys the binding key identified by
// uuid_bytes, removing it from the registry and zeroizing its key material.
//
// uuid_bytes must point to a 16-byte binding key UUID.
//
// Returns 0 on success, -1 if uuid_bytes is null or key was not found.
int32_t key_manager_destroy_binding_key(const uint8_t *uuid_bytes);

#endif // WS_KEY_CUSTODY_CORE_H_
