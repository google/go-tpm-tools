use crate::algorithms::{HpkeAlgorithm, KemAlgorithm};
use crate::crypto;
use crate::crypto::PublicKey;
use crate::protected_mem::Vault;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use uuid::Uuid;
use zeroize::Zeroize;

/// Represents the purpose of the Key and its associated algorithms.
#[derive(Clone)]
pub enum KeySpec {
    /// Represents the composite key used by the Key Protection Service for the decaps-and-encrypt flow.
    KemWithBindingPub {
        /// The KEM and binding public keys share the same algorithm suite.
        algo: HpkeAlgorithm,
        /// The KEM public key
        kem_public_key: PublicKey,
        /// Binding public key for HPKE encrypt after decaps
        binding_public_key: PublicKey,
    },
    Binding {
        algo: HpkeAlgorithm,
        /// The Binding key-pair
        binding_public_key: PublicKey,
    },
}

/// Internal Rust struct to hold the Key Metadata
#[derive(Clone)]
pub struct KeyMetadata {
    /// UUID key handle for internal tracking
    pub id: Uuid,
    pub created_at: Instant,
    /// TTL-bound deletion time
    pub delete_after: Instant,
    /// (non-secret) Cryptographic material
    pub spec: KeySpec,
}

/// Internal struct to hold the Key Metadata and the secret key material.
pub struct KeyRecord {
    pub meta: KeyMetadata,
    /// memfd_secrets backed secret key-material
    pub private_key: Vault,
}

pub type KeyHandle = Uuid;

/// Thread-safe registry for storing encryption keys.
#[derive(Default, Clone)]
pub struct KeyRegistry {
    keys: Arc<RwLock<HashMap<KeyHandle, KeyRecord>>>,
}

impl KeyRegistry {
    pub fn add_key(&self, record: KeyRecord) {
        let mut keys = self.keys.write().unwrap();
        keys.insert(record.meta.id, record);
    }
}

/// Helper function to create a KeyRecord and generate the underlying keypair.
pub fn create_key_record<F>(
    algo: HpkeAlgorithm,
    expiry_secs: u64,
    spec_builder: F,
) -> Result<KeyRecord, i32>
where
    F: FnOnce(HpkeAlgorithm, PublicKey) -> KeySpec,
{
    let (pub_key, mut priv_key) = match KemAlgorithm::try_from(algo.kem)
        .ok()
        .and_then(|k| crypto::generate_keypair(k).ok())
    {
        Some(pair) => pair,
        None => return Err(-1),
    };

    let id = Uuid::new_v4();
    let vault = Vault::new(&mut priv_key.0);
    priv_key.0.zeroize();
    let vault = vault.map_err(|_| -1)?;

    let record = KeyRecord {
        meta: KeyMetadata {
            id,
            created_at: Instant::now(),
            delete_after: Instant::now() + Duration::from_secs(expiry_secs),
            spec: spec_builder(algo, pub_key),
        },
        private_key: vault,
    };

    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};

    #[test]
    fn test_create_key_record_success() {
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };
        let expiry = 3600;

        let result = create_key_record(algo, expiry, |a, pk| KeySpec::Binding {
            algo: a,
            binding_public_key: pk,
        });

        assert!(result.is_ok());
        let record = result.unwrap();

        // Check metadata
        assert!(!record.meta.id.is_nil());
        assert!(record.meta.delete_after > record.meta.created_at);

        // Check spec
        if let KeySpec::Binding {
            algo: a,
            binding_public_key: pk,
        } = record.meta.spec
        {
            assert_eq!(a.kem, algo.kem);
            assert_eq!(pk.as_ref().len(), 32);
        } else {
            panic!("Unexpected KeySpec variant");
        }
    }

    #[test]
    fn test_create_key_record_kem_with_binding_pub_success() {
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };
        let binding_pubkey = PublicKey([42u8; 32].to_vec());
        let expiry = 3600;

        let result = create_key_record(algo, expiry, |a, pk| KeySpec::KemWithBindingPub {
            algo: a,
            kem_public_key: pk,
            binding_public_key: binding_pubkey.clone(),
        });

        assert!(result.is_ok());
        let record = result.unwrap();

        if let KeySpec::KemWithBindingPub {
            algo: a,
            kem_public_key: kpk,
            binding_public_key: bpk,
        } = record.meta.spec
        {
            assert_eq!(a.kem, algo.kem);
            assert_eq!(kpk.as_ref().len(), 32);
            assert_eq!(bpk, binding_pubkey);
        } else {
            panic!("Unexpected KeySpec variant");
        }
    }

    #[test]
    fn test_add_key() {
        let registry = KeyRegistry::default();
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        let record = create_key_record(algo, 3600, |a, pk| KeySpec::Binding {
            algo: a,
            binding_public_key: pk,
        })
        .expect("failed to create key");

        let id = record.meta.id;
        registry.add_key(record);

        // Access private field for testing
        let keys = registry.keys.read().unwrap();
        assert!(keys.contains_key(&id));
        assert_eq!(keys.get(&id).unwrap().meta.id, id);
    }
}
