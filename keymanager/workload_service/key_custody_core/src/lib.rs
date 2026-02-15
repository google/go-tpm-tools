use km_common::algorithms::HpkeAlgorithm;
use km_common::crypto::PublicKey;
use km_common::key_types::{KeyRecord, KeyRegistry, KeySpec};
use std::slice;
use std::sync::LazyLock;
use std::time::Duration;
use uuid::Uuid;
use zeroize::Zeroize;

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
use km_common::ffi::KmHpkeAlgorithm;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn key_manager_generate_binding_keypair(
    algo: KmHpkeAlgorithm,
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
    match generate_binding_keypair_internal(algo.into(), expiry_secs) {
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

/// Decrypts a ciphertext using a key from the registry.
///
/// ## Arguments
/// * `handle` - The 16-byte UUID of the key to use (as bytes).
/// * `enc` - The encapsulated key.
/// * `enc_len` - The length of the encapsulated key.
/// * `ciphertext` - The ciphertext to decrypt.
/// * `ciphertext_len` - The length of the ciphertext.
/// * `aad` - Associated data (optional/can be empty).
/// * `aad_len` - The length of the associated data.
/// * `out_plaintext` - Buffer to write the plaintext to.
/// * `out_plaintext_len` - Pointer to the size of the output buffer. Updated with actual size.
///
/// ## Returns
/// * `0` on success.
/// * `-1` on error (key not found, decryption failed, invalid input).
/// * `-2` if output buffer is too small.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn key_manager_open(
    handle: *const u8,
    enc: *const u8,
    enc_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    aad: *const u8,
    aad_len: usize,
    out_plaintext: *mut u8,
    out_plaintext_len: *mut usize,
) -> i32 {
    use km_common::key_types::KeySpec;
    use km_common::crypto::PrivateKey;

    if handle.is_null()
        || enc.is_null()
        || ciphertext.is_null()
        || out_plaintext.is_null()
        || out_plaintext_len.is_null()
        || (aad_len > 0 && aad.is_null())
    {
        return -1;
    }

    let handle_bytes = slice::from_raw_parts(handle, 16);
    let enc = slice::from_raw_parts(enc, enc_len);
    let ciphertext = slice::from_raw_parts(ciphertext, ciphertext_len);
    let aad = if aad_len > 0 {
        slice::from_raw_parts(aad, aad_len)
    } else {
        &[]
    };

    let id = match Uuid::from_slice(handle_bytes) {
        Ok(id) => id,
        Err(_) => return -1,
    };

    let record = match KEY_REGISTRY.get_key(&id) {
        Ok(r) => r,
        Err(_) => return -1,
    };

    let (algo_spec, priv_key_vault) = match &record.meta.spec {
        KeySpec::Binding { algo, .. } => (algo, &record.private_key),
        _ => return -1,
    };

    // Assuming we use the binding key to decrypt.
    let priv_key = match PrivateKey::try_from(priv_key_vault.as_bytes().to_vec()) {
        Ok(k) => k,
        Err(_) => return -1,
    };

    match km_common::crypto::hpke_open(&priv_key, enc, ciphertext, aad, algo_spec) {
        Ok(plaintext) => {
            let pt_bytes = plaintext.as_slice();
            if *out_plaintext_len < pt_bytes.len() {
                return -2;
            }
            let out_buf = slice::from_raw_parts_mut(out_plaintext, *out_plaintext_len);
            out_buf[..pt_bytes.len()].copy_from_slice(pt_bytes);
            *out_plaintext_len = pt_bytes.len();
            0
        }
        Err(_) => -1,
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
        let algo = KmHpkeAlgorithm {
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
        let algo = KmHpkeAlgorithm {
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
        let algo = KmHpkeAlgorithm {
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
        let pubkey_len: usize = pubkey_bytes.len();
        let algo = KmHpkeAlgorithm {
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
    fn test_key_manager_open_success() {
        let mut uuid_bytes = [0u8; 16];
        let mut pubkey_bytes = [0u8; 32];
        let mut pubkey_len: usize = pubkey_bytes.len();
        let algo = KmHpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        // 1. Generate keypair
        unsafe {
            key_manager_generate_binding_keypair(
                algo,
                3600,
                uuid_bytes.as_mut_ptr(),
                pubkey_bytes.as_mut_ptr(),
                pubkey_len,
            );
        }

        // 2. Encrypt something for this key
        let pt = b"secret message";
        let aad = b"test aad";
        // Convert KmHpkeAlgorithm to HpkeAlgorithm for helper calls
        let hpke_algo: HpkeAlgorithm = algo.into();
        let (enc, ct) = km_common::crypto::hpke_seal_raw(&pubkey_bytes, pt, aad, &hpke_algo).unwrap();

        // 3. Decrypt using key_manager_open
        let mut out_pt = [0u8; 64];
        let mut out_pt_len = out_pt.len();
        let result = unsafe {
            key_manager_open(
                uuid_bytes.as_ptr(),
                enc.as_ptr(),
                enc.len(),
                ct.as_ptr(),
                ct.len(),
                aad.as_ptr(),
                aad.len(),
                out_pt.as_mut_ptr(),
                &mut out_pt_len,
            )
        };

        assert_eq!(result, 0);
        assert_eq!(out_pt_len, pt.len());
        assert_eq!(&out_pt[..out_pt_len], pt);
    }

    #[test]
    fn test_key_manager_open_invalid_uuid() {
        let uuid_bytes = [0u8; 16];
        let mut out_pt = [0u8; 64];
        let mut out_pt_len = out_pt.len();
        let result = unsafe {
            key_manager_open(
                uuid_bytes.as_ptr(),
                [0u8; 32].as_ptr(),
                32,
                [0u8; 32].as_ptr(),
                32,
                [0u8; 8].as_ptr(),
                8,
                out_pt.as_mut_ptr(),
                &mut out_pt_len,
            )
        };
        assert_eq!(result, -1);
    }

    #[test]
    fn test_key_manager_open_buffer_too_small() {
        let mut uuid_bytes = [0u8; 16];
        let mut pubkey_bytes = [0u8; 32];
        let mut pubkey_len: usize = pubkey_bytes.len();
        let algo = KmHpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        // 1. Generate keypair
        unsafe {
            key_manager_generate_binding_keypair(
                algo,
                3600,
                uuid_bytes.as_mut_ptr(),
                pubkey_bytes.as_mut_ptr(),
                pubkey_len,
            );
        }

        // 2. Encrypt something
        let pt = b"secret message";
        // Convert KmHpkeAlgorithm to HpkeAlgorithm for helper calls
        let hpke_algo: HpkeAlgorithm = algo.into();
        let (enc, ct) = km_common::crypto::hpke_seal_raw(&pubkey_bytes, pt, b"", &hpke_algo).unwrap();

        let mut out_pt = [0u8; 5]; // smaller than pt
        let mut out_pt_len = out_pt.len();
        let result = unsafe {
            key_manager_open(
                uuid_bytes.as_ptr(),
                enc.as_ptr(),
                enc.len(),
                ct.as_ptr(),
                ct.len(),
                b"".as_ptr(),
                0,
                out_pt.as_mut_ptr(),
                &mut out_pt_len,
            )
        };

        assert_eq!(result, -2);
    }
}
