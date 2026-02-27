use km_common::algorithms::HpkeAlgorithm;
use km_common::crypto::PublicKey;
use km_common::key_types::{KeyRecord, KeyRegistry, KeySpec};
use prost::Message;
use std::slice;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use uuid::Uuid;

static KEY_REGISTRY: LazyLock<KeyRegistry> = LazyLock::new(|| {
    let registry = KeyRegistry::default();
    registry.start_reaper(Arc::new(AtomicBool::new(false)));
    registry
});

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
/// * `algo_ptr` - A pointer to the serialized HPKE algorithm proto bytes.
/// * `algo_len` - The length of the serialized HPKE algorithm proto bytes.
/// * `binding_pubkey` - A pointer to the binding public key bytes.
/// * `binding_pubkey_len` - The length of the binding public key.
/// * `expiry_secs` - The expiration time of the key in seconds from now.
/// * `out_uuid` - A pointer to a 16-byte buffer where the key UUID will be written.
/// * `out_pubkey` - A pointer to a buffer where the public key will be written.
/// * `out_pubkey_len` - The size of `out_pubkey` buffer.
///
/// ## Safety
/// This function is unsafe because it dereferences the provided raw pointers.
/// The caller must ensure that:
/// * `algo_ptr` points to a valid buffer of at least `algo_len` bytes.
/// * `binding_pubkey` points to a valid buffer of at least `binding_pubkey_len` bytes.
/// * `out_uuid` is either null or points to a valid 16-byte buffer.
/// * `out_pubkey` is either null or points to a valid buffer of at least `*out_pubkey_len` bytes.
/// * `out_pubkey_len` is either null or points to a valid `usize`.
///
/// ## Returns
/// * `0` on success.
/// * `-1` if an error occurred during key generation or if `binding_pubkey` is null/empty.
/// * `-2` if the `out_pubkey` buffer size does not match the key size.

#[unsafe(no_mangle)]
pub unsafe extern "C" fn key_manager_generate_kem_keypair(
    algo_ptr: *const u8,
    algo_len: usize,
    binding_pubkey: *const u8,
    binding_pubkey_len: usize,
    expiry_secs: u64,
    out_uuid: *mut u8,
    out_pubkey: *mut u8,
    out_pubkey_len: usize,
) -> i32 {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Safety Invariant Checks
        if binding_pubkey.is_null()
            || binding_pubkey_len == 0
            || out_pubkey.is_null()
            || out_uuid.is_null()
            || algo_ptr.is_null()
            || algo_len == 0
        {
            return -1;
        }

        // Convert to Safe Types
        let binding_pubkey_slice =
            unsafe { slice::from_raw_parts(binding_pubkey, binding_pubkey_len) };
        let algo_slice = unsafe { slice::from_raw_parts(algo_ptr, algo_len) };
        let out_uuid = unsafe { slice::from_raw_parts_mut(out_uuid, 16) };
        let out_pubkey = unsafe { slice::from_raw_parts_mut(out_pubkey, out_pubkey_len) };

        let binding_pubkey = match PublicKey::try_from(binding_pubkey_slice.to_vec()) {
            Ok(pk) => pk,
            Err(_) => return -1,
        };

        let algo = match HpkeAlgorithm::decode(algo_slice) {
            Ok(a) => a,
            Err(_) => return -1,
        };

        // Call Safe Internal Function
        match generate_kem_keypair_internal(algo, binding_pubkey, expiry_secs) {
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
    }))
    .unwrap_or(-1)
}

/// Destroys the KEM key associated with the given UUID.
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
pub unsafe extern "C" fn key_manager_destroy_kem_key(uuid_bytes: *const u8) -> i32 {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
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
    }))
    .unwrap_or(-1)
}

/// Internal function to decapsulate and reseal a shared secret.
fn decap_and_seal_internal(
    uuid: Uuid,
    encapsulated_key: &[u8],
    aad: &[u8],
    out_encapsulated_key: &mut [u8],
    out_ciphertext: &mut [u8],
) -> Result<(), i32> {
    // Get key record from registry
    let Some(key_record) = KEY_REGISTRY.get_key(&uuid) else {
        Err(-1)? // Key not found
    };

    let KeySpec::KemWithBindingPub {
        algo: hpke_algo,
        binding_public_key,
        ..
    } = &key_record.meta.spec
    else {
        Err(-1)? // Invalid key type
    };

    let priv_key = key_record.get_private_key();

    // Decapsulate
    let shared_secret = match km_common::crypto::decaps(&priv_key, encapsulated_key) {
        Ok(s) => s,
        Err(_) => return Err(-3),
    };

    // Seal
    match km_common::crypto::hpke_seal(binding_public_key, &shared_secret, aad, hpke_algo) {
        Ok((enc, ct)) => {
            if out_encapsulated_key.len() != enc.len() || out_ciphertext.len() != ct.len() {
                return Err(-2);
            }
            out_encapsulated_key.copy_from_slice(&enc);
            out_ciphertext.copy_from_slice(&ct);
            Ok(())
        }
        Err(_) => Err(-4),
    }
}

pub const MAX_ALGORITHM_LEN: usize = 128;
pub const MAX_PUBLIC_KEY_LEN: usize = 2048;

#[repr(C)]
pub struct KpsKeyInfo {
    pub uuid: [u8; 16],
    pub algorithm: [u8; MAX_ALGORITHM_LEN],
    pub algorithm_len: usize,
    pub pub_key: [u8; MAX_PUBLIC_KEY_LEN],
    pub pub_key_len: usize,
    pub binding_pub_key: [u8; MAX_PUBLIC_KEY_LEN],
    pub binding_pub_key_len: usize,
    pub remaining_lifespan_secs: u64,
}

impl Default for KpsKeyInfo {
    fn default() -> Self {
        KpsKeyInfo {
            uuid: [0; 16],
            algorithm: [0; MAX_ALGORITHM_LEN],
            algorithm_len: 0,
            pub_key: [0; MAX_PUBLIC_KEY_LEN],
            pub_key_len: 0,
            binding_pub_key: [0; MAX_PUBLIC_KEY_LEN],
            binding_pub_key_len: 0,
            remaining_lifespan_secs: 0,
        }
    }
}

fn enumerate_kem_keys_internal(
    entries: &mut [KpsKeyInfo],
    offset: usize,
) -> Result<(usize, bool), i32> {
    let (metas, total_count) = KEY_REGISTRY.list_all_keys(offset, entries.len());
    let count = metas.len();
    let has_more = offset + count < total_count;

    for (entry, meta) in entries.iter_mut().zip(metas.into_iter()) {
        let KeySpec::KemWithBindingPub {
            algo,
            kem_public_key: pub_key,
            binding_public_key: binding_pub_key,
            ..
        } = &meta.spec
        else {
            return Err(-1); // Implementation error, KPS should only contain KEM keys.
        };

        let algo_bytes = algo.encode_to_vec();

        if pub_key.as_bytes().len() > MAX_PUBLIC_KEY_LEN || algo_bytes.len() > MAX_ALGORITHM_LEN {
            debug_assert!(
                false,
                "Implementation error: Key size exceeds buffer limits! (algo={}, pub={})",
                algo_bytes.len(),
                pub_key.as_bytes().len()
            );
            return Err(-2); // Buffer Limit Exceeded
        }
        if binding_pub_key.as_bytes().len() > MAX_PUBLIC_KEY_LEN {
            debug_assert!(
                false,
                "Implementation error: Binding Key size exceeds buffer limits! (bpk={})",
                binding_pub_key.as_bytes().len()
            );
            return Err(-2);
        }

        let now = Instant::now();
        let remaining = meta.delete_after.saturating_duration_since(now).as_secs();

        *entry = KpsKeyInfo::default();

        entry.uuid.copy_from_slice(meta.id.as_bytes());

        entry.algorithm[..algo_bytes.len()].copy_from_slice(&algo_bytes);
        entry.algorithm_len = algo_bytes.len();

        entry.pub_key[..pub_key.as_bytes().len()].copy_from_slice(pub_key.as_bytes());
        entry.pub_key_len = pub_key.as_bytes().len();

        entry.binding_pub_key[..binding_pub_key.as_bytes().len()]
            .copy_from_slice(binding_pub_key.as_bytes());
        entry.binding_pub_key_len = binding_pub_key.as_bytes().len();

        entry.remaining_lifespan_secs = remaining;
    }

    Ok((count, has_more))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn key_manager_enumerate_kem_keys(
    out_entries: *mut KpsKeyInfo,
    max_entries: usize,
    offset: usize,
    out_has_more: Option<&mut bool>,
) -> i32 {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if out_entries.is_null() {
            return -1;
        }

        let entries = unsafe { slice::from_raw_parts_mut(out_entries, max_entries) };

        match enumerate_kem_keys_internal(entries, offset) {
            Ok((count, has_more)) => {
                if let Some(has_more_ref) = out_has_more {
                    *has_more_ref = has_more;
                }
                count as i32
            }
            Err(e) => e,
        }
    }))
    .unwrap_or(-1)
}

/// Decapsulates a shared secret using a stored KEM key and immediately reseals it using the associated binding public key.
///
/// ## Arguments
/// * `uuid_bytes` - A pointer to the 16-byte UUID of the KEM key.
/// * `encapsulated_key` - A pointer to the encapsulated key bytes (ciphertext from client).
/// * `encapsulated_key_len` - The length of the encapsulated key.
/// * `aad` - A pointer to the Additional Authenticated Data (AAD) for the sealing operation.
/// * `aad_len` - The length of the AAD.
/// * `out_encapsulated_key` - A pointer to a buffer where the new encapsulated key will be written.
/// * `out_encapsulated_key_len` - The size of `out_encapsulated_key`.
/// * `out_ciphertext` - A pointer to a buffer where the sealed ciphertext will be written.
/// * `out_ciphertext_len` -The size of `out_ciphertext`.
///
/// ## Safety
/// This function is unsafe because it dereferences raw pointers. The caller must ensure that:
/// * `uuid_bytes` points to a valid 16-byte buffer.
/// * `encapsulated_key` points to a valid buffer of `encapsulated_key_len` bytes.
/// * `aad` is either null or points to a valid buffer of `aad_len` bytes.
/// * `out_encapsulated_key` points to a valid buffer of `out_encapsulated_key_len` bytes.
/// * `out_ciphertext` points to a valid buffer of `out_ciphertext_len` bytes.
///
/// ## Returns
/// * `0` on success.
/// * `-1` if arguments are invalid or key is not found.
/// * `-2` if output buffers are too small.
/// * `-3` if decapsulation fails.
/// * `-4` if sealing (HPKE encryption) fails.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn key_manager_decap_and_seal(
    uuid_bytes: *const u8,
    encapsulated_key: *const u8,
    encapsulated_key_len: usize,
    aad: *const u8,
    aad_len: usize,
    out_encapsulated_key: *mut u8,
    out_encapsulated_key_len: usize,
    out_ciphertext: *mut u8,
    out_ciphertext_len: usize,
) -> i32 {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if uuid_bytes.is_null()
            || encapsulated_key.is_null()
            || encapsulated_key_len == 0
            || out_encapsulated_key.is_null()
            || out_encapsulated_key_len == 0
            || out_ciphertext.is_null()
            || out_ciphertext_len == 0
        {
            return -1;
        }

        // Convert to Safe Types
        let uuid_slice = unsafe { slice::from_raw_parts(uuid_bytes, 16) };
        let enc_key_slice =
            unsafe { slice::from_raw_parts(encapsulated_key, encapsulated_key_len) };
        let aad_slice = if !aad.is_null() && aad_len > 0 {
            unsafe { slice::from_raw_parts(aad, aad_len) }
        } else {
            &[]
        };
        let out_encapsulated_key_slice =
            unsafe { slice::from_raw_parts_mut(out_encapsulated_key, out_encapsulated_key_len) };
        let out_ciphertext_slice =
            unsafe { slice::from_raw_parts_mut(out_ciphertext, out_ciphertext_len) };

        let uuid = match Uuid::from_slice(uuid_slice) {
            Ok(u) => u,
            Err(_) => return -1,
        };

        // Call Safe Internal Function
        match decap_and_seal_internal(
            uuid,
            enc_key_slice,
            aad_slice,
            out_encapsulated_key_slice,
            out_ciphertext_slice,
        ) {
            Ok(_) => 0, // Success
            Err(e) => e,
        }
    }))
    .unwrap_or(-1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use km_common::algorithms::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
    use prost::Message;

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
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };
        let algo_bytes = algo.encode_to_vec();

        let result = unsafe {
            key_manager_generate_kem_keypair(
                algo_bytes.as_ptr(),
                algo_bytes.len(),
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
        // Invalid protobuf bytes
        let algo_bytes = vec![0xFF, 0xFF];

        let result = unsafe {
            key_manager_generate_kem_keypair(
                algo_bytes.as_ptr(),
                algo_bytes.len(),
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
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };
        let algo_bytes = algo.encode_to_vec();

        let result = unsafe {
            key_manager_generate_kem_keypair(
                algo_bytes.as_ptr(),
                algo_bytes.len(),
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
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };
        let algo_bytes = algo.encode_to_vec();

        let result = unsafe {
            key_manager_generate_kem_keypair(
                algo_bytes.as_ptr(),
                algo_bytes.len(),
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
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };
        let algo_bytes = algo.encode_to_vec();

        let result = unsafe {
            key_manager_generate_kem_keypair(
                algo_bytes.as_ptr(),
                algo_bytes.len(),
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
    fn test_destroy_kem_key_success() {
        let binding_pubkey = [1u8; 32];
        let mut uuid_bytes = [0u8; 16];
        let mut pubkey_bytes = [0u8; 32];
        let pubkey_len = pubkey_bytes.len();
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };
        let algo_bytes = algo.encode_to_vec();
        unsafe {
            let res = key_manager_generate_kem_keypair(
                algo_bytes.as_ptr(),
                algo_bytes.len(),
                binding_pubkey.as_ptr(),
                binding_pubkey.len(),
                3600,
                uuid_bytes.as_mut_ptr(),
                pubkey_bytes.as_mut_ptr(),
                pubkey_len,
            );
            assert_eq!(res, 0);
        }

        let result = unsafe { key_manager_destroy_kem_key(uuid_bytes.as_ptr()) };
        assert_eq!(result, 0);

        // Second destroy should fail
        let result = unsafe { key_manager_destroy_kem_key(uuid_bytes.as_ptr()) };
        assert_eq!(result, -1);
    }

    #[test]
    fn test_destroy_kem_key_not_found() {
        let uuid_bytes = [0u8; 16];
        let result = unsafe { key_manager_destroy_kem_key(uuid_bytes.as_ptr()) };
        assert_eq!(result, -1);
    }

    #[test]
    fn test_destroy_kem_key_null_ptr() {
        let result = unsafe { key_manager_destroy_kem_key(std::ptr::null()) };
        assert_eq!(result, -1);
    }

    #[test]
    fn test_enumerate_kem_keys_null_pointers() {
        let result = unsafe { key_manager_enumerate_kem_keys(std::ptr::null_mut(), 10, 0, None) };
        assert_eq!(result, -1);
    }

    #[test]
    fn test_enumerate_kem_keys_after_generate() {
        let binding_pubkey = [7u8; 32];
        let mut uuid_bytes = [0u8; 16];
        let mut pubkey_bytes = [0u8; 32];
        let pubkey_len: usize = 32;
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };
        // MUST encode to bytes
        let algo_bytes = algo.encode_to_vec();

        // Generate a key first.
        let rc = unsafe {
            key_manager_generate_kem_keypair(
                algo_bytes.as_ptr(),
                algo_bytes.len(),
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
        // Initialize with default/zero values. Note: Arrays are larger now.
        entries.resize_with(100, || KpsKeyInfo {
            uuid: [0; 16],
            algorithm: [0; MAX_ALGORITHM_LEN],
            algorithm_len: 0,
            pub_key: [0; MAX_PUBLIC_KEY_LEN],
            pub_key_len: 0,
            binding_pub_key: [0; MAX_PUBLIC_KEY_LEN],
            binding_pub_key_len: 0,
            remaining_lifespan_secs: 0,
        });
        let mut has_more = false;

        let rc = unsafe {
            // max_entries=100, offset=0
            key_manager_enumerate_kem_keys(
                entries.as_mut_ptr(),
                entries.len(),
                0,
                Some(&mut has_more),
            )
        };
        assert!(rc >= 1);
        let count = rc as usize;

        // Find our key in the results.
        let mut found = false;
        for i in 0..count {
            if entries[i].uuid == uuid_bytes {
                found = true;
                let encoded_algo = &entries[i].algorithm[..entries[i].algorithm_len];
                let decoded_algo = HpkeAlgorithm::decode(encoded_algo).unwrap();
                assert_eq!(decoded_algo.kem, KemAlgorithm::DhkemX25519HkdfSha256 as i32);
                assert_eq!(entries[i].pub_key_len, 32);
                assert!(entries[i].remaining_lifespan_secs > 0);
                break;
            }
        }
        assert!(found, "generated key not found in enumerate results");
    }

    #[test]
    fn test_enumerate_kem_keys_has_more() {
        // Assume there is at least one key from initialization/other tests or we'll generate one
        let mut uuid_bytes = [0u8; 16];
        let mut pubkey_bytes = [0u8; 32];
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };
        let algo_bytes = algo.encode_to_vec();

        // Let's explicitly generate a key so we know there's at least one in the registry
        unsafe {
            key_manager_generate_kem_keypair(
                algo_bytes.as_ptr(),
                algo_bytes.len(),
                [7u8; 32].as_ptr(), // fake binding key
                32,
                3600,
                uuid_bytes.as_mut_ptr(),
                pubkey_bytes.as_mut_ptr(),
                32,
            );
        }

        let mut entries: Vec<KpsKeyInfo> = Vec::with_capacity(256);
        entries.resize_with(100, || KpsKeyInfo {
            uuid: [0; 16],
            algorithm: [0; MAX_ALGORITHM_LEN],
            algorithm_len: 0,
            pub_key: [0; MAX_PUBLIC_KEY_LEN],
            pub_key_len: 0,
            binding_pub_key: [0; MAX_PUBLIC_KEY_LEN],
            binding_pub_key_len: 0,
            remaining_lifespan_secs: 0,
        });

        // 1. Ask for 0 entries. We should get has_more = true.
        let mut has_more = false;
        let rc = unsafe {
            key_manager_enumerate_kem_keys(entries.as_mut_ptr(), 0, 0, Some(&mut has_more))
        };
        assert_eq!(rc, 0);
        assert!(
            has_more,
            "has_more should be true when max_entries is 0 and keys exist"
        );

        // 2. Ask for 100 entries (which should cover all generated keys). has_more = false.
        has_more = true; // reset to true to ensure it gets set to false
        let rc = unsafe {
            key_manager_enumerate_kem_keys(
                entries.as_mut_ptr(),
                entries.len(),
                0,
                Some(&mut has_more),
            )
        };
        assert!(rc >= 1);
        assert!(
            !has_more,
            "has_more should be false when all keys are retrieved"
        );
    }

    #[test]
    fn test_decap_and_seal_success() {
        // 1. Setup binding key (receiver for seal)
        let binding_kem_algo = KemAlgorithm::DhkemX25519HkdfSha256;
        let (binding_pk, binding_sk) =
            km_common::crypto::generate_keypair(binding_kem_algo).unwrap();

        // 2. Generate KEM key in registry
        let mut uuid_bytes = [0u8; 16];
        let mut kem_pubkey_bytes = [0u8; 32];
        let kem_pubkey_len = 32;
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };
        let algo_bytes = algo.encode_to_vec();
        unsafe {
            key_manager_generate_kem_keypair(
                algo_bytes.as_ptr(),
                algo_bytes.len(),
                binding_pk.as_bytes().as_ptr(),
                binding_pk.as_bytes().len(),
                3600,
                uuid_bytes.as_mut_ptr(),
                kem_pubkey_bytes.as_mut_ptr(),
                kem_pubkey_len,
            )
        };

        // 3. Generate a "client" ciphertext/encapsulation targeting KEM key.
        let aad = b"test_aad";
        // We use `encap` to act as the client to generate a valid encapsulation
        let pub_key_obj = PublicKey::try_from(kem_pubkey_bytes.to_vec()).unwrap();
        let (client_shared_secret, client_enc) = km_common::crypto::encap(&pub_key_obj).unwrap();

        // Step 3: Call `decap_and_seal`.
        let mut out_enc_key = [0u8; 32];
        let out_enc_key_len = 32;
        let mut out_ct = [0u8; 48]; // 32 bytes secret + 16 tag
        let out_ct_len = 48;

        let result = unsafe {
            key_manager_decap_and_seal(
                uuid_bytes.as_ptr(),
                client_enc.as_ptr(),
                client_enc.len(),
                aad.as_ptr(),
                aad.len(),
                out_enc_key.as_mut_ptr(),
                out_enc_key_len,
                out_ct.as_mut_ptr(),
                out_ct_len,
            )
        };

        assert_eq!(result, 0);

        // 4. Verify we can decrypt the result using binding_sk
        let recovered_shared_secret =
            km_common::crypto::hpke_open(&binding_sk, &out_enc_key, &out_ct, aad, &algo)
                .expect("Failed to decrypt the resealed secret");

        assert_eq!(recovered_shared_secret.as_slice().len(), 32);

        // 5. Verify the recovered secret matches what decaps would produce
        // And also matches the original client shared secret
        assert_eq!(
            recovered_shared_secret.as_slice(),
            client_shared_secret.as_slice(),
            "Recovered secret mismatch"
        );
    }

    #[test]
    fn test_decap_and_seal_invalid_uuid() {
        let mut out_enc_key = [0u8; 32];
        let out_enc_key_len = 32;
        let mut out_ct = [0u8; 48];
        let out_ct_len = 48;

        let result = unsafe {
            key_manager_decap_and_seal(
                [0u8; 16].as_ptr(),
                [0u8; 32].as_ptr(),
                32,
                std::ptr::null(),
                0,
                out_enc_key.as_mut_ptr(),
                out_enc_key_len,
                out_ct.as_mut_ptr(),
                out_ct_len,
            )
        };

        assert_eq!(result, -1);
    }

    #[test]
    fn test_decap_and_seal_null_args() {
        let mut out_enc_key = [0u8; 32];
        let out_enc_key_len = 32;

        let result = unsafe {
            key_manager_decap_and_seal(
                std::ptr::null(),
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                out_enc_key.as_mut_ptr(),
                out_enc_key_len,
                std::ptr::null_mut(),
                0,
            )
        };

        assert_eq!(result, -1);
    }

    #[test]
    fn test_decap_and_seal_decaps_fail() {
        // 1. Setup binding key
        let binding_kem_algo = KemAlgorithm::DhkemX25519HkdfSha256;
        let (binding_pk, _) = km_common::crypto::generate_keypair(binding_kem_algo).unwrap();

        // 2. Generate KEM key
        let mut uuid_bytes = [0u8; 16];
        let mut kem_pubkey_bytes = [0u8; 32];
        let kem_pubkey_len = 32;
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };
        let algo_bytes = algo.encode_to_vec();
        let res = unsafe {
            key_manager_generate_kem_keypair(
                algo_bytes.as_ptr(),
                algo_bytes.len(),
                binding_pk.as_bytes().as_ptr(),
                binding_pk.as_bytes().len(),
                3600,
                uuid_bytes.as_mut_ptr(),
                kem_pubkey_bytes.as_mut_ptr(),
                kem_pubkey_len,
            )
        };
        assert_eq!(res, 0);

        // 3. Call with invalid encapsulated key (wrong length for X25519)
        let mut out_enc_key = [0u8; 32];
        let out_enc_key_len = 32;
        let mut out_ct = [0u8; 48];
        let out_ct_len = 48;

        let result = unsafe {
            key_manager_decap_and_seal(
                uuid_bytes.as_ptr(),
                [0u8; 31].as_ptr(),
                31,
                std::ptr::null(),
                0,
                out_enc_key.as_mut_ptr(),
                out_enc_key_len,
                out_ct.as_mut_ptr(),
                out_ct_len,
            )
        };

        assert_eq!(result, -3);
    }

    #[test]
    fn test_decap_and_seal_buffer_too_small() {
        // 1. Setup binding key
        let binding_kem_algo = KemAlgorithm::DhkemX25519HkdfSha256;
        let (binding_pk, _) = km_common::crypto::generate_keypair(binding_kem_algo).unwrap();

        // 2. Generate KEM key
        let mut uuid_bytes = [0u8; 16];
        let mut kem_pubkey_bytes = [0u8; 32];
        let kem_pubkey_len = 32;
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        let algo_bytes = algo.encode_to_vec();
        let res = unsafe {
            key_manager_generate_kem_keypair(
                algo_bytes.as_ptr(),
                algo_bytes.len(),
                binding_pk.as_bytes().as_ptr(),
                binding_pk.as_bytes().len(),
                3600,
                uuid_bytes.as_mut_ptr(),
                kem_pubkey_bytes.as_mut_ptr(),
                kem_pubkey_len,
            )
        };
        assert_eq!(res, 0, "Setup failed: key generation returned error");

        // 3. Generate valid client encapsulation
        let pub_key_obj = PublicKey::try_from(kem_pubkey_bytes.to_vec()).unwrap();
        let pt = km_common::crypto::secret_box::SecretBox::new(b"secret".to_vec());
        let (client_enc, _) = km_common::crypto::hpke_seal(&pub_key_obj, &pt, b"", &algo).unwrap();

        // 4. Call with small output buffers
        let mut out_enc_key = [0u8; 31]; // Small
        let out_enc_key_len = 31;
        let mut out_ct = [0u8; 47]; // Small
        let out_ct_len = 47;

        let result = unsafe {
            key_manager_decap_and_seal(
                uuid_bytes.as_ptr(),
                client_enc.as_ptr(),
                client_enc.len(),
                std::ptr::null(),
                0,
                out_enc_key.as_mut_ptr(),
                out_enc_key_len,
                out_ct.as_mut_ptr(),
                out_ct_len,
            )
        };

        assert_eq!(result, -2);
    }
}
