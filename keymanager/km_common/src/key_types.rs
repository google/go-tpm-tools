use crate::algorithms::HpkeAlgorithm;
use crate::protected_mem::Vault;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use uuid::Uuid;

/// Represents the purpose of the Key and its associated algorithms.
#[derive(Clone)]
pub enum KeySpec {
    /// Represents the composite key used by the Key Protection Service for the decaps-and-encrypt flow.
    KemWithBindingPub {
        /// The KEM and binding public keys share the same algorithm suite.
        algo: HpkeAlgorithm,
        /// The KEM public key
        kem_public_key: Vec<u8>,
        /// Binding public key for HPKE encrypt after decaps
        binding_public_key: Vec<u8>,
    },
    Binding {
        algo: HpkeAlgorithm,
        /// The Binding key-pair
        binding_public_key: Vec<u8>,
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
