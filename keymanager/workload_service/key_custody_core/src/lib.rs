use km_common::algorithms::HpkeAlgorithm;
use km_common::crypto::PublicKey;
use km_common::key_types::{KeyRecord, KeyRegistry, KeySpec};
use std::slice;
use std::sync::LazyLock;
use std::time::Duration;
use uuid::Uuid;

static KEY_REGISTRY: LazyLock<KeyRegistry> = LazyLock::new(KeyRegistry::default);

/// Internal function to generate a binding keypair and store it in the registry.
fn generate_binding_keypair_internal(
    algo: HpkeAlgorithm,
    expiry_secs: u64,
) -> Result<(uuid::Uuid, PublicKey), i32> {
    let result = KeyRecord::create_binding_key(algo, Duration::from_secs(expiry_secs));

    match result {
        Ok(record) => {
            let id = record.meta.id;
            let pubkey = match &record.meta.spec {
                KeySpec::Binding {
                    binding_public_key, ..
                } => binding_public_key.clone(),
                _ => return Err(-1),
            };
            KEY_REGISTRY.add_key(record);
            Ok((id, pubkey))
        }
        Err(_) => Err(-1),
    }
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
/// * `-2` if the `out_pubkey` buffer size does not match the key size.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn key_manager_generate_binding_keypair(
    algo: HpkeAlgorithm,
    expiry_secs: u64,
    out_uuid: *mut u8,
    out_pubkey: *mut u8,
    out_pubkey_len: usize,
) -> i32 {
    // Safety Invariant Checks
    if out_pubkey.is_null() || out_uuid.is_null() {
        return -1;
    }

    // Convert to Safe Types
    let out_uuid = unsafe { slice::from_raw_parts_mut(out_uuid, 16) };
    let out_pubkey = unsafe { slice::from_raw_parts_mut(out_pubkey, out_pubkey_len) };

    // Call Safe Internal Function
    match generate_binding_keypair_internal(algo, expiry_secs) {
        Ok((id, pubkey)) => {
            if out_pubkey_len != pubkey.as_bytes().len() {
                return -2;
            }
            out_uuid.copy_from_slice(id.as_bytes());
            out_pubkey.copy_from_slice(pubkey.as_bytes());
            0 // Success
        }
        Err(e) => e,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn key_manager_destroy_binding_key(uuid_bytes: *const u8) -> i32 {
    if uuid_bytes.is_null() {
        return -1;
    }
    let uuid = unsafe {
        let mut bytes = [0u8; 16];
        std::ptr::copy_nonoverlapping(uuid_bytes, bytes.as_mut_ptr(), 16);
        Uuid::from_bytes(bytes)
    };

    match KEY_REGISTRY.remove_key(&uuid) {
        Some(_) => 0, // Success
        None => -1,   // Not found
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use km_common::algorithms::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};

    #[test]
    fn test_create_binding_keypair_internal_success() {
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        let result = generate_binding_keypair_internal(algo, 3600);
        assert!(result.is_ok());

        let (id, _) = result.unwrap();

        // Verify UUID is present
        assert!(!id.is_nil());
    }

    #[test]
    fn test_generate_binding_keypair_ffi_success() {
        let mut uuid_bytes = [0u8; 16];
        let mut pubkey_bytes = [0u8; 32];
        let pubkey_len: usize = pubkey_bytes.len();
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
                pubkey_len,
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
        let mut pubkey_bytes = [0u8; 32];
        let pubkey_len: usize = pubkey_bytes.len();
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
                pubkey_len,
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
                0,
            )
        };

        assert_eq!(result, -1);
    }

    #[test]
    fn test_generate_binding_keypair_invalid_pubkey_len() {
        let mut uuid_bytes = [0u8; 16];
        let mut pubkey_bytes = [0u8; 64];
        let pubkey_len: usize = pubkey_bytes.len();
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
                pubkey_len,
            )
        };

        assert_eq!(result, -2);
        assert_eq!(uuid_bytes, [0u8; 16]); // Should remain untouched/zero
        assert_eq!(&pubkey_bytes[..32], &[0u8; 32]); // Should remain untouched/zero
    }

    #[test]
    fn test_destroy_binding_key_success() {
        let mut uuid_bytes = [0u8; 16];
        let mut pubkey_bytes = [0u8; 32];
        let pubkey_len: usize = pubkey_bytes.len();
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        unsafe {
            key_manager_generate_binding_keypair(
                algo,
                3600,
                uuid_bytes.as_mut_ptr(),
                pubkey_bytes.as_mut_ptr(),
                pubkey_len,
            )
        };

        let result = key_manager_destroy_binding_key(uuid_bytes.as_ptr());
        assert_eq!(result, 0);

        // Second destroy should fail
        let result = key_manager_destroy_binding_key(uuid_bytes.as_ptr());
        assert_eq!(result, -1);
    }

    #[test]
    fn test_destroy_binding_key_not_found() {
        let uuid_bytes = [0u8; 16];
        let result = key_manager_destroy_binding_key(uuid_bytes.as_ptr());
        assert_eq!(result, -1);
    }

    #[test]
    fn test_destroy_binding_key_null_ptr() {
        let result = key_manager_destroy_binding_key(std::ptr::null());
        assert_eq!(result, -1);
    }
}
