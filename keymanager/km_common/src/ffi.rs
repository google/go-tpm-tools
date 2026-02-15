use crate::algorithms::{AeadAlgorithm, HpkeAlgorithm, KdfAlgorithm, KemAlgorithm};

// KmHpkeAlgorithm is the stable C ABI representation of algorithms::HpkeAlgorithm.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KmHpkeAlgorithm {
    pub kem: i32,
    pub kdf: i32,
    pub aead: i32,
}

pub const KM_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256: i32 = 1;
pub const KM_KDF_ALGORITHM_HKDF_SHA256: i32 = 1;
pub const KM_AEAD_ALGORITHM_AES_256_GCM: i32 = 1;

// Keep FFI constants synchronized with algorithms.proto enum values at compile time.
const _: [(); KM_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256 as usize] =
    [(); KemAlgorithm::DhkemX25519HkdfSha256 as usize];
const _: [(); KM_KDF_ALGORITHM_HKDF_SHA256 as usize] = [(); KdfAlgorithm::HkdfSha256 as usize];
const _: [(); KM_AEAD_ALGORITHM_AES_256_GCM as usize] = [(); AeadAlgorithm::Aes256Gcm as usize];

impl From<KmHpkeAlgorithm> for HpkeAlgorithm {
    fn from(value: KmHpkeAlgorithm) -> Self {
        Self {
            kem: value.kem,
            kdf: value.kdf,
            aead: value.aead,
        }
    }
}
