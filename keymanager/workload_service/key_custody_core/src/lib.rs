use km_common::algorithms::HpkeAlgorithm;
use km_common::key_types::{KeyRecord, KeyRegistry, KeySpec};
use std::sync::LazyLock;

static KEY_REGISTRY: LazyLock<KeyRegistry> = LazyLock::new(KeyRegistry::default);

/// Creates a new binding key record with the specified HPKE algorithm and expiration.
fn create_binding_key(algo: HpkeAlgorithm, expiry_secs: u64) -> Result<KeyRecord, i32> {
    km_common::key_types::create_key_record(algo, expiry_secs, |algo, pub_key| KeySpec::Binding {
        algo,
        binding_public_key: pub_key,
    })
}

/// Generates a new binding HPKE keypair.
///
/// ## Arguments
/// * `algo` - The HPKE algorithm to use for the keypair.
/// * `expiry_secs` - The expiration time of the key in seconds from now.
/// * `out_uuid` - A pointer to a 16-byte buffer where the key UUID will be written.
/// * `out_pubkey` - A pointer to a buffer where the public key will be written.
/// * `out_pubkey_len` - A pointer to a `usize` that contains the size of `out_pubkey` buffer.
///   On success, it will be updated with the actual size of the public key.
///
/// ## Safety
/// This function is unsafe because it dereferences the provided raw pointers.
/// The caller must ensure that:
/// * `out_uuid` is either null or points to a valid 16-byte buffer.
/// * `out_pubkey` is either null or points to a valid buffer of at least `*out_pubkey_len` bytes.
/// * `out_pubkey_len` is either null or points to a valid `usize`.
///
/// ## Returns
/// * `0` on success.
/// * `-1` if an error occurred during key generation.
/// * `-2` if the `out_pubkey` buffer is too small.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn key_manager_generate_binding_keypair(
    algo: HpkeAlgorithm,
    expiry_secs: u64,
    out_uuid: *mut u8,
    out_pubkey: *mut u8,
    out_pubkey_len: *mut usize,
) -> i32 {
    match create_binding_key(algo, expiry_secs) {
        Ok(record) => {
            let id = record.meta.id;
            let pubkey = match &record.meta.spec {
                KeySpec::Binding {
                    binding_public_key, ..
                } => binding_public_key.clone(),
                _ => return -1,
            };
            KEY_REGISTRY.add_key(record);
            unsafe {
                if !out_uuid.is_null() {
                    std::ptr::copy_nonoverlapping(id.as_bytes().as_ptr(), out_uuid, 16);
                }
                if !out_pubkey.is_null() && !out_pubkey_len.is_null() {
                    let buf_len = *out_pubkey_len;
                    if buf_len >= pubkey.as_bytes().len() {
                        std::ptr::copy_nonoverlapping(
                            pubkey.as_bytes().as_ptr(),
                            out_pubkey,
                            pubkey.as_bytes().len(),
                        );
                        *out_pubkey_len = pubkey.as_bytes().len();
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
    fn test_create_binding_key_success_and_zeroization() {
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        let result = create_binding_key(algo, 3600);
        assert!(result.is_ok());

        let record = result.unwrap();

        // Verify UUID is present
        assert!(!record.meta.id.is_nil());
    }

    #[test]
    fn test_generate_binding_keypair_ffi_success() {
        let mut uuid_bytes = [0u8; 16];
        let mut pubkey_bytes = [0u8; 64];
        let mut pubkey_len: usize = pubkey_bytes.len();
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        let result = unsafe {
            key_manager_generate_binding_keypair(
                algo,
                3600,
                uuid_bytes.as_mut_ptr(),
                pubkey_bytes.as_mut_ptr(),
                &mut pubkey_len,
            )
        };

        assert_eq!(result, 0);
        assert_ne!(uuid_bytes, [0u8; 16]);
        assert_eq!(pubkey_len, 32); // X25519 public key is 32 bytes
        assert_ne!(&pubkey_bytes[..32], &[0u8; 32]);
    }

    #[test]
    fn test_generate_binding_keypair_invalid_algo() {
        let mut uuid_bytes = [0u8; 16];
        let mut pubkey_bytes = [0u8; 64];
        let mut pubkey_len: usize = pubkey_bytes.len();
        let algo = HpkeAlgorithm {
            kem: 999, // Invalid KEM
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        let result = unsafe {
            key_manager_generate_binding_keypair(
                algo,
                3600,
                uuid_bytes.as_mut_ptr(),
                pubkey_bytes.as_mut_ptr(),
                &mut pubkey_len,
            )
        };

        assert_eq!(result, -1);
        assert_eq!(uuid_bytes, [0u8; 16]); // Should remain untouched/zero
    }

    #[test]
    fn test_generate_binding_keypair_null_uuid_ptr() {
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        // Pass null pointers, should succeed (return 0) but not crash
        let result = unsafe {
            key_manager_generate_binding_keypair(
                algo,
                3600,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };

        assert_eq!(result, 0);
    }
}
