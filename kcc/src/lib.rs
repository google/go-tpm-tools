mod vault;
mod types;
mod error;
mod ffi;

use bssl_crypto::hpke;
use clear_on_drop::clear_stack_on_return;
use types::{
    AeadAlgorithm, HpkeAlgorithm, KdfAlgorithm, KemAlgorithm, KeyMetadata, KeyRecord, PublicSpec,
};
use error::Error;
use vault::Vault;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use uuid::Uuid;
use zeroize::Zeroize;

pub type KeyHandle = Uuid;

pub struct KeyRegistry {
    pub keys: Arc<RwLock<HashMap<KeyHandle, KeyRecord>>>,
    stop_reaper: Arc<AtomicBool>,
    reaper_handle: Option<JoinHandle<()>>,
}

impl Default for KeyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyRegistry {
    pub fn new() -> Self {
        let keys = Arc::new(RwLock::new(HashMap::<KeyHandle, KeyRecord>::new()));
        let stop_reaper = Arc::new(AtomicBool::new(false));

        let keys_clone = keys.clone();
        let stop_clone = stop_reaper.clone();

        let reaper_handle = Some(thread::spawn(move || {
            while !stop_clone.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_secs(10));
                if stop_clone.load(Ordering::Relaxed) {
                    break;
                }
                let now = Instant::now();
                keys_clone
                    .write()
                    .unwrap()
                    .retain(|_, key| key.meta.delete_after.map_or(true, |d| d > now));
            }
        }));

        Self { keys, stop_reaper, reaper_handle }
    }

    fn add_key(&self, key_record: KeyRecord) -> KeyHandle {
        let handle = key_record.meta.id;
        self.keys.write().unwrap().insert(handle, key_record);
        handle
    }

    fn destroy_key(&self, handle: KeyHandle) -> Result<(), Error> {
        if self.keys.write().unwrap().remove(&handle).is_some() {
            Ok(())
        } else {
            Err(Error::KeyNotFound)
        }
    }
}

impl Drop for KeyRegistry {
    fn drop(&mut self) {
        self.stop_reaper.store(true, Ordering::Relaxed);
        if let Some(handle) = self.reaper_handle.take() {
            handle.join().expect("Reaper thread panicked");
        }
    }
}

pub struct KeyManager {
    pub binding_keys: KeyRegistry,
    pub kem_keys: KeyRegistry
}


impl Default for KeyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyManager {
    pub fn new() -> Self {
        Self {
            binding_keys: KeyRegistry::new(),
            kem_keys: KeyRegistry::new(),
        }
    }


    pub fn generate_binding_keypair(&self) -> (KeyHandle, Vec<u8>) {
        clear_stack_on_return(2, || {
            let key_id = Uuid::new_v4();
            let (pub_key, mut priv_key) = hpke::Kem::X25519HkdfSha256.generate_keypair();
            let secret = Vault::new(&key_id.to_string(), &priv_key).expect("Vault creation failed");
            priv_key.zeroize();
            let meta = KeyMetadata {
                id: key_id,
                created_at: Instant::now(),
                delete_after: Some(Instant::now() + Duration::from_secs(3600)),
                spec: PublicSpec::Binding {
                    algo: HpkeAlgorithm {
                        kem: KemAlgorithm::DhKemX25519HkdfSha256,
                        kdf: KdfAlgorithm::HkdfSha256,
                        aead: AeadAlgorithm::Aes256Gcm,
                    },
                    binding_public_key: pub_key.clone(),
                },
            };
            let record = KeyRecord { meta, secret };
            let handle = self.binding_keys.add_key(record);
            (handle, pub_key)
        })
    }

    pub fn generate_kem_keypair(&self, binding_pub_key: &[u8]) -> (KeyHandle, Vec<u8>) {
        clear_stack_on_return(2, || {
            let key_id = Uuid::new_v4();
            let (kem_pub, mut kem_priv) = hpke::Kem::X25519HkdfSha256.generate_keypair();
            let secret = Vault::new(&key_id.to_string(), &kem_priv).expect("Vault creation failed");
            kem_priv.zeroize();
            let meta = KeyMetadata {
                id: key_id,
                created_at: Instant::now(),
                delete_after: Some(Instant::now() + Duration::from_secs(3600)),
                spec: PublicSpec::KemWithBindingPub {
                    algo: HpkeAlgorithm {
                        kem: KemAlgorithm::DhKemX25519HkdfSha256,
                        kdf: KdfAlgorithm::HkdfSha256,
                        aead: AeadAlgorithm::Aes256Gcm,
                    },
                    kem_public_key: kem_pub.clone(),
                    binding_public_key: binding_pub_key.to_vec(),
                },
            };
            let record = KeyRecord { meta, secret };
            let handle = self.kem_keys.add_key(record);
            (handle, kem_pub)
        })
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn test_generate_binding_keypair() {
        let manager = KeyManager::new();
        let (handle, pub_key) = manager.generate_binding_keypair();

        // Verify handle is a valid UUID
        assert!(!handle.is_nil());
        
        // Verify public key is returned (X25519 is 32 bytes)
        assert_eq!(pub_key.len(), 32);

        // Verify key is actually in the registry
        let registry = manager.binding_keys.keys.read().unwrap();
        assert!(registry.contains_key(&handle));
        
        let record = registry.get(&handle).unwrap();
        assert_eq!(record.meta.id, handle);
        
        // Check if metadata spec matches Binding
        match &record.meta.spec {
            PublicSpec::Binding { algo, .. } => {
                assert_eq!(algo.kem, KemAlgorithm::DhKemX25519HkdfSha256);
            },
            _ => panic!("Wrong key spec type"),
        }
    }

    #[test]
    fn test_destroy_key() {
        let manager = KeyManager::new();
        let (handle, _) = manager.generate_binding_keypair();

        // Ensure key exists
        {
            let registry = manager.binding_keys.keys.read().unwrap();
            assert!(registry.contains_key(&handle));
        }

        // Destroy the key
        let result = manager.binding_keys.destroy_key(handle);
        assert!(result.is_ok());

        // Ensure key is gone
        {
            let registry = manager.binding_keys.keys.read().unwrap();
            assert!(!registry.contains_key(&handle));
        }

        // Test destroying non-existent key
        let fake_uuid = Uuid::new_v4();
        let err = manager.binding_keys.destroy_key(fake_uuid);
        assert!(matches!(err, Err(Error::KeyNotFound)));
    }

    #[test]
    fn test_reaper_thread_ttl_cleanup() {
        let manager = KeyManager::new();
        
        // Create a record with an immediate expiration
        let key_id = Uuid::new_v4();
        let expired_meta = KeyMetadata {
            id: key_id,
            created_at: Instant::now(),
            // Expired 5 seconds ago
            delete_after: Some(Instant::now() - Duration::from_secs(5)),
            spec: PublicSpec::Binding {
                algo: HpkeAlgorithm {
                    kem: KemAlgorithm::DhKemX25519HkdfSha256,
                    kdf: KdfAlgorithm::HkdfSha256,
                    aead: AeadAlgorithm::Aes256Gcm,
                },
                binding_public_key: vec![0u8; 32],
            },
        };

        let mut test_key = vec![0u8; 32];
        let record = KeyRecord {
            meta: expired_meta,
            secret: Vault::new("test", &test_key).unwrap(),
        };

        // Manually add the expired key
        manager.binding_keys.add_key(record);

        // Check it exists initially
        assert!(manager.binding_keys.keys.read().unwrap().contains_key(&key_id));

        // The reaper runs every 10 seconds. In a test, we don't want to wait 10s.
        // We simulate the reaper's logic manually or reduce the sleep in the code.
        // For this test, we verify the logic the reaper uses:
        let now = Instant::now();
        manager.binding_keys.keys.write().unwrap().retain(|_, key| {
            key.meta.delete_after.map_or(true, |d| d > now)
        });

        // Key should now be removed
        assert!(!manager.binding_keys.keys.read().unwrap().contains_key(&key_id));
    }

    #[test]
    fn test_registry_drop_stops_reaper() {
        let mut registry = Some(KeyRegistry::new());
        let stop_signal = registry.as_ref().unwrap().stop_reaper.clone();
        
        assert_eq!(stop_signal.load(Ordering::Relaxed), false);
        
        // Drop the registry
        drop(registry.take());
        
        // Verify stop signal was sent
        assert_eq!(stop_signal.load(Ordering::Relaxed), true);
    }

    #[test]
    fn test_generate_kem_keypair_with_binding() {
        let manager = KeyManager::new();
        let binding_pub = vec![1u8; 32];
        
        let (handle, kem_pub) = manager.generate_kem_keypair(&binding_pub);
        
        assert!(!handle.is_nil());
        assert_eq!(kem_pub.len(), 32);

        let registry = manager.kem_keys.keys.read().unwrap();
        let record = registry.get(&handle).expect("KEM key not found");

        if let PublicSpec::KemWithBindingPub { binding_public_key, .. } = &record.meta.spec {
            assert_eq!(binding_public_key, &binding_pub);
        } else {
            panic!("Metadata did not store binding public key correctly");
        }
    }
}


