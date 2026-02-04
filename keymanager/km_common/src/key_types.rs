use crate::algorithms::HpkeAlgorithm;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use uuid::Uuid;

/// Represents the purpose of the Key and its associated algorithms.
#[derive(Debug, Clone)]
pub enum KeySpec {
    // Represents the composite key used by the Key Protection Service for the decaps-and-encrypt flow.
    KemWithBindingPub {
        // The KEM and binding public keys share the same algorithm suite.
        algo: HpkeAlgorithm,
        kem_public_key: Vec<u8>,     // The KEM key-pair
        binding_public_key: Vec<u8>, // Binding public key for HPKE encrypt after decaps
    },
    Binding {
        algo: HpkeAlgorithm,
        binding_public_key: Vec<u8>, // The Binding key-pair
    },
}

// Internal Rust struct to hold the Key Metadata
#[derive(Debug, Clone)]
pub struct KeyMetadata {
    pub id: Uuid,              // UUID key handle for internal tracking
    pub created_at: Instant,
    pub delete_after: Instant, // TTL-bound deletion time
    pub spec: KeySpec,         // (non-secret) Cryptographic material
}

#[derive(Debug)] // zerioize components before dropping
pub struct Vault {
    // placeholder
}

#[derive(Debug)]
pub struct KeyRecord {
    pub meta: KeyMetadata,
    pub private_key: Vault, // memfd_secrets backed secret key-material
}

pub type KeyHandle = Uuid;

#[derive(Default, Clone, Debug)]
pub struct KeyRegistry {
    keys: Arc<RwLock<HashMap<KeyHandle, KeyRecord>>>,
}
