use crate::vault::Vault;
use std::time::Instant;
use uuid::Uuid;

#[derive(Debug)]
pub struct KeyMetadata {
    pub id: Uuid,
    pub created_at: Instant,
    pub delete_after: Option<Instant>,
    pub spec: PublicSpec,
}

#[derive(Debug)]
pub enum PublicSpec {
    KemWithBindingPub { algo: HpkeAlgorithm, kem_public_key: Vec<u8>, binding_public_key: Vec<u8> },
    Binding { algo: HpkeAlgorithm, binding_public_key: Vec<u8> },
    Sek { algo: SigningAlgorithm, verifying_key: Vec<u8> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum KemAlgorithm {
    DhKemX25519HkdfSha256 = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum KdfAlgorithm {
    HkdfSha256 = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AeadAlgorithm {
    Aes256Gcm = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HpkeAlgorithm {
    pub kem: KemAlgorithm,
    pub kdf: KdfAlgorithm,
    pub aead: AeadAlgorithm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SigningAlgorithm {
    Unspecified = 0,
    Ed25519 = 1,
}

pub struct KeyRecord {
    pub meta: KeyMetadata,
    pub secret: Vault,
}