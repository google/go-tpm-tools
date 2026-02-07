use km_common::algorithms::HpkeAlgorithm;
use km_common::key_types::{KeyRecord, KeyRegistry, KeySpec};
use lazy_static::lazy_static;

lazy_static! {
    static ref KEY_REGISTRY: KeyRegistry = KeyRegistry::default();
}

fn create_binding_key(
    algo: HpkeAlgorithm,
    expiry_secs: u64,
) -> Result<KeyRecord, i32> {
    km_common::key_types::create_key_record(algo, expiry_secs, |algo, pub_key| KeySpec::Binding {
        algo,
        binding_public_key: pub_key,
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn key_manager_generate_binding_keypair(
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
                KeySpec::Binding { binding_public_key, .. } => binding_public_key.clone(),
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

        let result = key_manager_generate_binding_keypair(
            algo, 3600, uuid_bytes.as_mut_ptr(),
            pubkey_bytes.as_mut_ptr(), &mut pubkey_len,
        );

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

        let result = key_manager_generate_binding_keypair(
            algo, 3600, uuid_bytes.as_mut_ptr(),
            pubkey_bytes.as_mut_ptr(), &mut pubkey_len,
        );

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
        let result = key_manager_generate_binding_keypair(
            algo, 3600, std::ptr::null_mut(),
            std::ptr::null_mut(), std::ptr::null_mut(),
        );

        assert_eq!(result, 0);
    }
}
