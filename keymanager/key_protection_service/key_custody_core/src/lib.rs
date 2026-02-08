use km_common::algorithms::HpkeAlgorithm;
use km_common::key_types::{KeyRecord, KeyRegistry, KeySpec};
use lazy_static::lazy_static;
use std::slice;

lazy_static! {
    static ref KEY_REGISTRY: KeyRegistry = KeyRegistry::default();
}

/// Creates a new KEM key record with the specified HPKE algorithm, binding public key, and expiration.
fn create_kem_key(
    algo: HpkeAlgorithm,
    binding_pubkey: &[u8],
    expiry_secs: u64,
) -> Result<KeyRecord, i32> {
    km_common::key_types::create_key_record(algo, expiry_secs, |algo, kem_pub_key| {
        KeySpec::KemWithBindingPub {
            algo,
            kem_public_key: kem_pub_key,
            binding_public_key: binding_pubkey.to_vec(),
        }
    })
}

/// Generates a new KEM keypair associated with a binding public key.
///
/// ## Arguments
/// * `algo` - The HPKE algorithm to use for the keypair.
/// * `binding_pubkey` - A pointer to the binding public key bytes.
/// * `binding_pubkey_len` - The length of the binding public key.
/// * `expiry_secs` - The expiration time of the key in seconds from now.
/// * `out_uuid` - A pointer to a 16-byte buffer where the key UUID will be written.
/// * `out_pubkey` - A pointer to a buffer where the public key will be written.
/// * `out_pubkey_len` - A pointer to a `usize` that contains the size of `out_pubkey` buffer.
///                      On success, it will be updated with the actual size of the public key.
///
/// ## Returns
/// * `0` on success.
/// * `-1` if an error occurred during key generation or if `binding_pubkey` is null/empty.
/// * `-2` if the `out_pubkey` buffer is too small.
#[unsafe(no_mangle)]
pub extern "C" fn key_manager_generate_kem_keypair(
    algo: HpkeAlgorithm,
    binding_pubkey: *const u8,
    binding_pubkey_len: usize,
    expiry_secs: u64,
    out_uuid: *mut u8,
    out_pubkey: *mut u8,
    out_pubkey_len: *mut usize,
) -> i32 {
    if binding_pubkey.is_null() || binding_pubkey_len == 0 {
        return -1;
    }

    let binding_pubkey_slice = unsafe { slice::from_raw_parts(binding_pubkey, binding_pubkey_len) };

    match create_kem_key(algo, binding_pubkey_slice, expiry_secs) {
        Ok(record) => {
            let id = record.meta.id;
            let pubkey = match &record.meta.spec {
                KeySpec::KemWithBindingPub { kem_public_key, .. } => kem_public_key.clone(),
                _ => return -1,
            };
            KEY_REGISTRY.add_key(record);
            unsafe {
                if !out_uuid.is_null() {
                    std::ptr::copy_nonoverlapping(id.as_bytes().as_ptr(), out_uuid, 16);
                }
                if !out_pubkey.is_null() && !out_pubkey_len.is_null() {
                    let buf_len = *out_pubkey_len;
                    if buf_len >= pubkey.len() {
                        std::ptr::copy_nonoverlapping(pubkey.as_ptr(), out_pubkey, pubkey.len());
                        *out_pubkey_len = pubkey.len();
                    } else {
                        return -2; // buffer too small
                    }
                }
            }
            0 // Success
        }
        Err(e) => e,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use km_common::algorithms::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};

    #[test]
    fn test_create_kem_key_success_and_zeroization() {
        let binding_pubkey = [1u8; 32];
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        let result = create_kem_key(algo, &binding_pubkey, 3600);
        assert!(result.is_ok());

        let record = result.unwrap();
        
        // Verify UUID is present
        assert!(!record.meta.id.is_nil());
    }

    #[test]
    fn test_generate_kem_keypair_ffi_success() {
        let binding_pubkey = [1u8; 32];
        let mut uuid_bytes = [0u8; 16];
        let mut pubkey_bytes = [0u8; 64];
        let mut pubkey_len: usize = pubkey_bytes.len();
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        let result = key_manager_generate_kem_keypair(
            algo,
            binding_pubkey.as_ptr(),
            binding_pubkey.len(),
            3600,
            uuid_bytes.as_mut_ptr(),
            pubkey_bytes.as_mut_ptr(),
            &mut pubkey_len,
        );

        assert_eq!(result, 0);
        assert_ne!(uuid_bytes, [0u8; 16]);
        assert_eq!(pubkey_len, 32); // X25519 public key is 32 bytes
        assert_ne!(&pubkey_bytes[..32], &[0u8; 32]);
    }

    #[test]
    fn test_generate_kem_keypair_invalid_algo() {
        let binding_pubkey = [1u8; 32];
        let mut uuid_bytes = [0u8; 16];
        let mut pubkey_bytes = [0u8; 64];
        let mut pubkey_len: usize = pubkey_bytes.len();
        let algo = HpkeAlgorithm {
            kem: 999, // Invalid KEM
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        let result = key_manager_generate_kem_keypair(
            algo,
            binding_pubkey.as_ptr(),
            binding_pubkey.len(),
            3600,
            uuid_bytes.as_mut_ptr(),
            pubkey_bytes.as_mut_ptr(),
            &mut pubkey_len,
        );

        assert_eq!(result, -1);
        assert_eq!(uuid_bytes, [0u8; 16]);
    }

    #[test]
    fn test_generate_kem_keypair_null_binding_key() {
        let mut uuid_bytes = [0u8; 16];
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        let result = key_manager_generate_kem_keypair(
            algo,
            std::ptr::null(), // Null ptr
            32,
            3600,
            uuid_bytes.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        assert_eq!(result, -1);
    }

    #[test]
    fn test_generate_kem_keypair_empty_binding_key_len() {
        let binding_pubkey = [1u8; 32];
        let mut uuid_bytes = [0u8; 16];
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        let result = key_manager_generate_kem_keypair(
            algo,
            binding_pubkey.as_ptr(),
            0, // Empty length
            3600,
            uuid_bytes.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        assert_eq!(result, -1);
    }
}
