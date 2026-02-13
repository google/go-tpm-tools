use km_common::algorithms::HpkeAlgorithm;
use km_common::crypto::PublicKey;
use km_common::key_types::{KeyRecord, KeyRegistry, KeySpec};
use prost::Message;
use std::slice;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use uuid::Uuid;
use zeroize::Zeroize;

static KEY_REGISTRY: LazyLock<KeyRegistry> = LazyLock::new(|| {
    let registry = KeyRegistry::default();
    registry.start_reaper(Arc::new(AtomicBool::new(false)));
    registry
});

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
/// * `algo_ptr` - A pointer to the serialized HPKE algorithm proto bytes.
/// * `algo_len` - The length of the serialized HPKE algorithm proto bytes.
/// * `expiry_secs` - The expiration time of the key in seconds from now.
/// * `out_uuid` - A pointer to a 16-byte buffer where the key UUID will be written.
/// * `out_pubkey` - A pointer to a buffer where the public key will be written.
/// * `out_pubkey_len` - A pointer to a `usize` that contains the size of `out_pubkey` buffer.
///   On success, it will be updated with the actual size of the public key.
///
/// ## Safety
/// This function is unsafe because it dereferences the provided raw pointers.
/// The caller must ensure that:
/// * `algo_ptr` points to a valid buffer of at least `algo_len` bytes.
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
    algo_ptr: *const u8,
    algo_len: usize,
    expiry_secs: u64,
    out_uuid: *mut u8,
    out_pubkey: *mut u8,
    out_pubkey_len: usize,
) -> i32 {
    // Safety Invariant Checks
    if out_pubkey.is_null() || out_uuid.is_null() || algo_ptr.is_null() || algo_len == 0 {
        return -1;
    }

    // Convert to Safe Types
    let algo_slice = unsafe { slice::from_raw_parts(algo_ptr, algo_len) };
    let out_uuid = unsafe { slice::from_raw_parts_mut(out_uuid, 16) };
    let out_pubkey = unsafe { slice::from_raw_parts_mut(out_pubkey, out_pubkey_len) };

    let algo = match HpkeAlgorithm::decode(algo_slice) {
        Ok(a) => a,
        Err(_) => return -1,
    };

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

/// Destroys the binding key associated with the given UUID.
///
/// ## Arguments
/// * `uuid_bytes` - A pointer to a 16-byte buffer containing the key UUID.
///
/// ## Safety
/// This function is unsafe because it dereferences the provided raw pointer.
/// The caller must ensure that `uuid_bytes` points to a valid 16-byte buffer.
///
/// ## Returns
/// * `0` on success.
/// * `-1` if the UUID pointer is null or the key was not found.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn key_manager_destroy_binding_key(uuid_bytes: *const u8) -> i32 {
    if uuid_bytes.is_null() {
        return -1;
    }
    let bytes = unsafe { slice::from_raw_parts(uuid_bytes, 16) };
    let uuid = Uuid::from_bytes(bytes.try_into().expect("invalid UUID bytes"));

    match KEY_REGISTRY.remove_key(&uuid) {
        Some(_) => 0, // Success
        None => -1,   // Not found
    }
}

/// Decrypts a ciphertext using the binding key associated with the given UUID.
///
/// ## Arguments
/// * `uuid_bytes` - A pointer to a 16-byte buffer containing the key UUID.
/// * `enc` - A pointer to the encapsulated shared secret.
/// * `enc_len` - The length of the encapsulated shared secret.
/// * `ciphertext` - A pointer to the ciphertext to decrypt.
/// * `ciphertext_len` - The length of the ciphertext.
/// * `aad` - A pointer to the additional authenticated data.
/// * `aad_len` - The length of the additional authenticated data.
/// * `out_plaintext` - A pointer to a buffer where the decrypted plaintext will be written.
/// * `out_plaintext_len` - A pointer to a `usize` that contains the size of `out_plaintext` buffer.
///   On success, it will be updated with the actual size of the plaintext.
///
/// ## Safety
/// This function is unsafe because it dereferences raw pointers. The caller must ensure that:
/// * `uuid_bytes` points to a valid 16-byte buffer.
/// * `enc` points to a valid buffer of at least `enc_len` bytes.
/// * `ciphertext` points to a valid buffer of at least `ciphertext_len` bytes.
/// * `aad` points to a valid buffer of at least `aad_len` bytes.
/// * `out_plaintext` is either null or points to a valid buffer of at least `*out_plaintext_len` bytes.
/// * `out_plaintext_len` points to a valid `usize`.
///
/// ## Returns
/// * `0` on success.
/// * `-1` if an error occurred (e.g., key not found, null pointers).
/// * `-2` if the `out_plaintext` buffer is too small.
/// * `-3` if decryption failed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn key_manager_open(
    uuid_bytes: *const u8,
    enc: *const u8,
    enc_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    aad: *const u8,
    aad_len: usize,
    out_plaintext: *mut u8,
    out_plaintext_len: *mut usize,
) -> i32 {
    if uuid_bytes.is_null()
        || enc.is_null()
        || ciphertext.is_null()
        || aad.is_null()
        || out_plaintext_len.is_null()
    {
        return -1;
    }

    let uuid = unsafe {
        let mut bytes = [0u8; 16];
        std::ptr::copy_nonoverlapping(uuid_bytes, bytes.as_mut_ptr(), 16);
        Uuid::from_bytes(bytes)
    };

    let record = match KEY_REGISTRY.get_key(&uuid) {
        Some(r) => r,
        None => return -1,
    };

    let algo = match &record.meta.spec {
        KeySpec::Binding { algo, .. } => algo,
        _ => return -1,
    };

    let enc_slice = unsafe { std::slice::from_raw_parts(enc, enc_len) };
    let ct_slice = unsafe { std::slice::from_raw_parts(ciphertext, ciphertext_len) };
    let aad_slice = unsafe { std::slice::from_raw_parts(aad, aad_len) };

    // Convert Vault bytes to SecretBox for active usage
    let secret =
        km_common::crypto::secret_box::SecretBox::new(record.private_key.as_bytes().to_vec());
    let priv_key = km_common::crypto::PrivateKey::from_secret(secret);

    match km_common::crypto::hpke_open(&priv_key, enc_slice, ct_slice, aad_slice, algo) {
        Ok(mut pt) => {
            unsafe {
                let buf_len = *out_plaintext_len;
                if buf_len < pt.as_slice().len() {
                    return -2;
                }
                if out_plaintext.is_null() {
                    return -1;
                }
                std::ptr::copy_nonoverlapping(
                    pt.as_slice().as_ptr(),
                    out_plaintext,
                    pt.as_slice().len(),
                );
                *out_plaintext_len = pt.as_slice().len();
            }
            0
        }
        Err(_) => -3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use km_common::algorithms::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
    use prost::Message;

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
        let algo_bytes = algo.encode_to_vec();

        let result = unsafe {
            key_manager_generate_binding_keypair(
                algo_bytes.as_ptr(),
                algo_bytes.len(),
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
        // Invalid protobuf bytes
        let algo_bytes = vec![0xFF, 0xFF];

        let result = unsafe {
            key_manager_generate_binding_keypair(
                algo_bytes.as_ptr(),
                algo_bytes.len(),
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
        let algo_bytes = algo.encode_to_vec();

        // Pass null pointers, should succeed (return 0) but not crash
        let result = unsafe {
            key_manager_generate_binding_keypair(
                algo_bytes.as_ptr(),
                algo_bytes.len(),
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
        let algo_bytes = algo.encode_to_vec();

        let result = unsafe {
            key_manager_generate_binding_keypair(
                algo_bytes.as_ptr(),
                algo_bytes.len(),
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
            let res = key_manager_generate_binding_keypair(
                algo,
                3600,
                uuid_bytes.as_mut_ptr(),
                pubkey_bytes.as_mut_ptr(),
                pubkey_len,
            );
            assert_eq!(res, 0);
        };

        let result = unsafe { key_manager_destroy_binding_key(uuid_bytes.as_ptr()) };
        assert_eq!(result, 0);

        // Second destroy should fail
        let result = unsafe { key_manager_destroy_binding_key(uuid_bytes.as_ptr()) };
        assert_eq!(result, -1);
    }

    #[test]
    fn test_destroy_binding_key_not_found() {
        let uuid_bytes = [0u8; 16];
        let result = unsafe { key_manager_destroy_binding_key(uuid_bytes.as_ptr()) };
        assert_eq!(result, -1);
    }

    #[test]
    fn test_destroy_binding_key_null_ptr() {
        let result = unsafe { key_manager_destroy_binding_key(std::ptr::null()) };
        assert_eq!(result, -1);
    }

    #[test]
    fn test_key_manager_open_success() {
        let mut uuid_bytes = [0u8; 16];
        let mut pubkey_bytes = [0u8; 32];
        let mut pubkey_len: usize = pubkey_bytes.len();
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        // 1. Generate keypair
        key_manager_generate_binding_keypair(
            algo.clone(),
            3600,
            uuid_bytes.as_mut_ptr(),
            pubkey_bytes.as_mut_ptr(),
            &mut pubkey_len,
        );

        // 2. Encrypt something for this key
        let pt = b"secret message";
        let aad = b"test aad";
        let (enc, ct) = km_common::crypto::hpke_seal(&pubkey_bytes, pt, aad, &algo).unwrap();

        // 3. Decrypt using key_manager_open
        let mut out_pt = [0u8; 64];
        let mut out_pt_len = out_pt.len();
        let result = key_manager_open(
            uuid_bytes.as_ptr(),
            enc.as_ptr(),
            enc.len(),
            ct.as_ptr(),
            ct.len(),
            aad.as_ptr(),
            aad.len(),
            out_pt.as_mut_ptr(),
            &mut out_pt_len,
        );

        assert_eq!(result, 0);
        assert_eq!(out_pt_len, pt.len());
        assert_eq!(&out_pt[..out_pt_len], pt);
    }

    #[test]
    fn test_key_manager_open_invalid_uuid() {
        let uuid_bytes = [0u8; 16];
        let mut out_pt = [0u8; 64];
        let mut out_pt_len = out_pt.len();
        let result = key_manager_open(
            uuid_bytes.as_ptr(),
            [0u8; 32].as_ptr(),
            32,
            [0u8; 32].as_ptr(),
            32,
            [0u8; 8].as_ptr(),
            8,
            out_pt.as_mut_ptr(),
            &mut out_pt_len,
        );
        assert_eq!(result, -1);
    }

    #[test]
    fn test_key_manager_open_buffer_too_small() {
        let mut uuid_bytes = [0u8; 16];
        let mut pubkey_bytes = [0u8; 32];
        let mut pubkey_len: usize = pubkey_bytes.len();
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        key_manager_generate_binding_keypair(
            algo.clone(),
            3600,
            uuid_bytes.as_mut_ptr(),
            pubkey_bytes.as_mut_ptr(),
            &mut pubkey_len,
        );

        let pt = b"secret message";
        let (enc, ct) = km_common::crypto::hpke_seal(&pubkey_bytes, pt, b"", &algo).unwrap();

        let mut out_pt = [0u8; 5]; // smaller than pt
        let mut out_pt_len = out_pt.len();
        let result = key_manager_open(
            uuid_bytes.as_ptr(),
            enc.as_ptr(),
            enc.len(),
            ct.as_ptr(),
            ct.len(),
            b"".as_ptr(),
            0,
            out_pt.as_mut_ptr(),
            &mut out_pt_len,
        );

        assert_eq!(result, -2);
    }

    #[test]
    fn test_key_manager_open_success() {
        let mut uuid_bytes = [0u8; 16];
        let mut pubkey_bytes = [0u8; 32];
        let mut pubkey_len: usize = pubkey_bytes.len();
        let algo = HpkeAlgorithm {
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
                &mut pubkey_len,
            );
        }

        // 2. Encrypt something for this key
        let pt = b"secret message";
        let aad = b"test aad";
        let pub_key =
            km_common::crypto::PublicKey::try_from(pubkey_bytes[..pubkey_len].to_vec()).unwrap();
        let pt_box = km_common::crypto::secret_box::SecretBox::new(pt.to_vec());
        let (enc, ct) = km_common::crypto::hpke_seal(&pub_key, &pt_box, aad, &algo).unwrap();

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
                &mut pubkey_len,
            );
        }

        let pt = b"secret message";
        let pub_key =
            km_common::crypto::PublicKey::try_from(pubkey_bytes[..pubkey_len].to_vec()).unwrap();
        let pt_box = km_common::crypto::secret_box::SecretBox::new(pt.to_vec());
        let (enc, ct) = km_common::crypto::hpke_seal(&pub_key, &pt_box, b"", &algo).unwrap();

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
