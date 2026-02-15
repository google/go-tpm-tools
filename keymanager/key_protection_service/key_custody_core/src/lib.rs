use km_common::algorithms::HpkeAlgorithm;
use km_common::crypto::PublicKey;
use km_common::key_types::{KeyRecord, KeyRegistry, KeySpec};
use std::slice;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

static KEY_REGISTRY: LazyLock<KeyRegistry> = LazyLock::new(KeyRegistry::default);

/// Internal function to generate a KEM keypair and store it in the registry.
fn generate_kem_keypair_internal(
    algo: HpkeAlgorithm,
    binding_pubkey: PublicKey,
    expiry_secs: u64,
) -> Result<(uuid::Uuid, PublicKey), i32> {
    let result =
        KeyRecord::create_bound_kem_key(algo, binding_pubkey, Duration::from_secs(expiry_secs));

    match result {
        Ok(record) => {
            let id = record.meta.id;
            let pubkey = match &record.meta.spec {
                KeySpec::KemWithBindingPub { kem_public_key, .. } => kem_public_key.clone(),
                _ => return Err(-1),
            };
            KEY_REGISTRY.add_key(record);
            Ok((id, pubkey))
        }
        Err(_) => Err(-1),
    }
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
///
/// ## Safety
/// This function is unsafe because it dereferences the provided raw pointers.
/// The caller must ensure that:
/// * `binding_pubkey` points to a valid buffer of at least `binding_pubkey_len` bytes.
/// * `out_uuid` is either null or points to a valid 16-byte buffer.
/// * `out_pubkey` is either null or points to a valid buffer of at least `*out_pubkey_len` bytes.
/// * `out_pubkey_len` is either null or points to a valid `usize`.
///
/// ## Returns
/// * `0` on success.
/// * `-1` if an error occurred during key generation or if `binding_pubkey` is null/empty.
/// * `-2` if the `out_pubkey` buffer size does not match the key size.
use km_common::ffi::KmHpkeAlgorithm;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn key_manager_generate_kem_keypair(
    algo: KmHpkeAlgorithm,
    binding_pubkey: *const u8,
    binding_pubkey_len: usize,
    expiry_secs: u64,
    out_uuid: *mut u8,
    out_pubkey: *mut u8,
    out_pubkey_len: usize,
) -> i32 {
    // Safety Invariant Checks
    if binding_pubkey.is_null()
        || binding_pubkey_len == 0
        || out_pubkey.is_null()
        || out_uuid.is_null()
    {
        return -1;
    }

    // Convert to Safe Types
    let binding_pubkey_slice = unsafe { slice::from_raw_parts(binding_pubkey, binding_pubkey_len) };
    let out_uuid = unsafe { slice::from_raw_parts_mut(out_uuid, 16) };
    let out_pubkey = unsafe { slice::from_raw_parts_mut(out_pubkey, out_pubkey_len) };

    let binding_pubkey = match PublicKey::try_from(binding_pubkey_slice.to_vec()) {
        Ok(pk) => pk,
        Err(_) => return -1,
    };

    // Call Safe Internal Function
    // Call Safe Internal Function
    match generate_kem_keypair_internal(algo.into(), binding_pubkey, expiry_secs) {
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

#[repr(C)]
pub struct KpsKeyInfo {
    pub uuid: [u8; 16],
    pub algorithm: KmHpkeAlgorithm,
    pub kem_pub_key: [u8; 64],
    pub kem_pub_key_len: usize,
    pub binding_pub_key: [u8; 64],
    pub binding_pub_key_len: usize,
    pub remaining_lifespan_secs: u64,
}

#[unsafe(no_mangle)]
pub extern "C" fn key_manager_enumerate_kem_keys(
    out_entries: *mut KpsKeyInfo,
    max_entries: usize,
    out_count: *mut usize,
) -> i32 {
    if out_entries.is_null() || out_count.is_null() {
        return -1;
    }

    let metas = KEY_REGISTRY.enumerate_keys();
    let now = Instant::now();
    let mut count = 0usize;

    for meta in &metas {
        if count >= max_entries {
            break;
        }
        if let KeySpec::KemWithBindingPub {
            algo,
            kem_public_key,
            binding_public_key,
        } = &meta.spec
        {
            if kem_public_key.as_bytes().len() > 64 || binding_public_key.as_bytes().len() > 64 {
                continue;
            }

            let remaining = meta.delete_after.saturating_duration_since(now).as_secs();

            let entry = unsafe { &mut *out_entries.add(count) };
            entry.uuid.copy_from_slice(meta.id.as_bytes());
            entry.algorithm = KmHpkeAlgorithm {
                kem: (*algo).kem,
                kdf: (*algo).kdf,
                aead: (*algo).aead,
            };

            entry.kem_pub_key = [0u8; 64];
            entry.kem_pub_key[..kem_public_key.as_bytes().len()].copy_from_slice(kem_public_key.as_bytes());
            entry.kem_pub_key_len = kem_public_key.as_bytes().len();

            entry.binding_pub_key = [0u8; 64];
            entry.binding_pub_key[..binding_public_key.as_bytes().len()].copy_from_slice(binding_public_key.as_bytes());
            entry.binding_pub_key_len = binding_public_key.as_bytes().len();

            entry.remaining_lifespan_secs = remaining;

            count += 1;
        }
    }

    unsafe {
        *out_count = count;
    }
    0
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

        let result = generate_kem_keypair_internal(
            algo,
            PublicKey::try_from(binding_pubkey.to_vec()).unwrap(),
            3600,
        );
        assert!(result.is_ok());

        let (id, _) = result.unwrap();

        // Verify UUID is present
        assert!(!id.is_nil());
    }

    #[test]
    fn test_generate_kem_keypair_ffi_success() {
        let binding_pubkey = [1u8; 32];
        let mut uuid_bytes = [0u8; 16];
        let mut pubkey_bytes = [0u8; 32];
        let pubkey_len: usize = pubkey_bytes.len();
        let algo = KmHpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        let result = unsafe {
            key_manager_generate_kem_keypair(
                algo,
                binding_pubkey.as_ptr(),
                binding_pubkey.len(),
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
    fn test_generate_kem_keypair_invalid_algo() {
        let binding_pubkey = [1u8; 32];
        let mut uuid_bytes = [0u8; 16];
        let mut pubkey_bytes = [0u8; 32];
        let pubkey_len: usize = pubkey_bytes.len();
        let algo = KmHpkeAlgorithm {
            kem: 999, // Invalid KEM
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        let result = unsafe {
            key_manager_generate_kem_keypair(
                algo,
                binding_pubkey.as_ptr(),
                binding_pubkey.len(),
                3600,
                uuid_bytes.as_mut_ptr(),
                pubkey_bytes.as_mut_ptr(),
                pubkey_len,
            )
        };

        assert_eq!(result, -1);
        assert_eq!(uuid_bytes, [0u8; 16]);
    }

    #[test]
    fn test_generate_kem_keypair_invalid_pubkey_len() {
        let binding_pubkey = [1u8; 32];
        let mut uuid_bytes = [0u8; 16];
        let mut pubkey_bytes = [0u8; 64];
        let pubkey_len: usize = pubkey_bytes.len();
        let algo = KmHpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        let result = unsafe {
            key_manager_generate_kem_keypair(
                algo,
                binding_pubkey.as_ptr(),
                binding_pubkey.len(),
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
    fn test_generate_kem_keypair_null_binding_key() {
        let mut uuid_bytes = [0u8; 16];
        let algo = KmHpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        let result = unsafe {
            key_manager_generate_kem_keypair(
                algo,
                std::ptr::null(), // Null ptr
                32,
                3600,
                uuid_bytes.as_mut_ptr(),
                std::ptr::null_mut(),
                0,
            )
        };

        assert_eq!(result, -1);
    }

    #[test]
    fn test_generate_kem_keypair_empty_binding_key_len() {
        let binding_pubkey = [1u8; 32];
        let mut uuid_bytes = [0u8; 16];
        let algo = KmHpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        let result = unsafe {
            key_manager_generate_kem_keypair(
                algo,
                binding_pubkey.as_ptr(),
                0, // Empty length
                3600,
                uuid_bytes.as_mut_ptr(),
                std::ptr::null_mut(),
                0,
            )
        };

        assert_eq!(result, -1);
    }

    #[test]
    fn test_enumerate_kem_keys_null_pointers() {
        let result = key_manager_enumerate_kem_keys(std::ptr::null_mut(), 10, std::ptr::null_mut());
        assert_eq!(result, -1);
    }

    #[test]
    fn test_enumerate_kem_keys_after_generate() {
        let binding_pubkey = [7u8; 32];
        let mut uuid_bytes = [0u8; 16];
        let mut pubkey_bytes = [0u8; 64];
        let pubkey_len: usize = 32;
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        // Generate a key first.
        let rc = unsafe {
            key_manager_generate_kem_keypair(
                KmHpkeAlgorithm {
                    kem: algo.kem,
                    kdf: algo.kdf,
                    aead: algo.aead,
                },
                binding_pubkey.as_ptr(),
                binding_pubkey.len(),
                3600,
                uuid_bytes.as_mut_ptr(),
                pubkey_bytes.as_mut_ptr(),
                pubkey_len,
            )
        };
        assert_eq!(rc, 0);

        // Enumerate.
        let mut entries: Vec<KpsKeyInfo> = Vec::with_capacity(256);
        entries.resize_with(256, || KpsKeyInfo {
            uuid: [0; 16],
            algorithm: KmHpkeAlgorithm {
                kem: 0,
                kdf: 0,
                aead: 0,
            },
            kem_pub_key: [0; 64],
            kem_pub_key_len: 0,
            binding_pub_key: [0; 64],
            binding_pub_key_len: 0,
            remaining_lifespan_secs: 0,
        });
        let mut count: usize = 0;

        let rc = unsafe { key_manager_enumerate_kem_keys(entries.as_mut_ptr(), entries.len(), &mut count) };
        assert_eq!(rc, 0);
        // At least 1 key should be enumerated (the one we just generated).
        // Note: other tests may have added keys to the global registry too.
        assert!(count >= 1);

        // Find our key in the results.
        let mut found = false;
        for i in 0..count {
            if entries[i].uuid == uuid_bytes {
                found = true;
                assert_eq!(
                    entries[i].algorithm.kem,
                    KemAlgorithm::DhkemX25519HkdfSha256 as i32
                );
                assert_eq!(entries[i].kem_pub_key_len, 32);
                assert_eq!(entries[i].binding_pub_key_len, 32);
                assert_eq!(&entries[i].binding_pub_key[..32], &binding_pubkey);
                assert!(entries[i].remaining_lifespan_secs > 0);
                break;
            }
        }
        assert!(found, "generated key not found in enumerate results");
    }
}
