use crate::algorithms::{AeadAlgorithm, HpkeAlgorithm, KdfAlgorithm, KemAlgorithm};
pub mod secret_box;
use crate::crypto::secret_box::SecretBox;
#[cfg(any(test, feature = "test-utils"))]
use bssl_crypto::{aead, aead::Aead, hkdf};
use clear_on_drop::clear_stack_on_return;
use thiserror::Error;

mod x25519;
pub use x25519::{X25519PrivateKey, X25519PublicKey};

const CLEAR_STACK_PAGES: usize = 2;

/// A trait for public keys with algorithm-specific implementations.
pub(crate) trait PublicKeyOps: Send + Sync {
    /// Encrypts a plaintext using HPKE.
    ///
    /// Returns a tuple containing the encapsulated key and the ciphertext respectively.
    fn hpke_seal_internal(
        &self,
        plaintext: &SecretBox,
        aad: &[u8],
        algo: &HpkeAlgorithm,
    ) -> Result<(Vec<u8>, Vec<u8>), Error>;

    /// Returns the raw bytes of the public key.
    fn as_bytes(&self) -> &[u8];
}

/// A trait for private keys with algorithm-specific implementations.
pub(crate) trait PrivateKeyOps: Send + Sync {
    /// Decapsulates the shared secret from an encapsulated key.
    ///
    /// Returns the decapsulated shared secret as a `SecretBox`.
    fn decaps_internal(&self, enc: &[u8]) -> Result<SecretBox, Error>;

    /// Decrypts a ciphertext using HPKE.
    ///
    /// Returns the decrypted plaintext as a `SecretBox`.
    fn hpke_open_internal(
        &self,
        enc: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
        algo: &HpkeAlgorithm,
    ) -> Result<SecretBox, Error>;
}

/// A wrapper enum for different public key types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    X25519(X25519PublicKey),
}

impl PublicKey {
    /// Returns the raw bytes of the public key.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            PublicKey::X25519(pk) => pk.as_bytes(),
        }
    }
}

impl TryFrom<Vec<u8>> for PublicKey {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = value.try_into().map_err(|_| Error::KeyLenMismatch)?;
        Ok(PublicKey::X25519(X25519PublicKey(bytes)))
    }
}

impl PublicKeyOps for PublicKey {
    fn hpke_seal_internal(
        &self,
        plaintext: &SecretBox,
        aad: &[u8],
        algo: &HpkeAlgorithm,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        match self {
            PublicKey::X25519(pk) => pk.hpke_seal_internal(plaintext, aad, algo),
        }
    }

    fn as_bytes(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// A wrapper enum for different private key types.
pub enum PrivateKey {
    X25519(X25519PrivateKey),
}

impl From<SecretBox> for PrivateKey {
    fn from(secret: SecretBox) -> Self {
        PrivateKey::X25519(X25519PrivateKey(secret))
    }
}

impl From<PrivateKey> for SecretBox {
    fn from(key: PrivateKey) -> SecretBox {
        match key {
            PrivateKey::X25519(sk) => SecretBox::from(sk),
        }
    }
}

impl PrivateKeyOps for PrivateKey {
    fn decaps_internal(&self, enc: &[u8]) -> Result<SecretBox, Error> {
        match self {
            PrivateKey::X25519(sk) => sk.decaps_internal(enc),
        }
    }

    fn hpke_open_internal(
        &self,
        enc: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
        algo: &HpkeAlgorithm,
    ) -> Result<SecretBox, Error> {
        match self {
            PrivateKey::X25519(sk) => sk.hpke_open_internal(enc, ciphertext, aad, algo),
        }
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Key length mismatch")]
    KeyLenMismatch,
    #[error("Decapsulation error")]
    DecapsError,
    #[error("HPKE decryption error")]
    HpkeDecryptionError,
    #[error("HPKE encryption error")]
    HpkeEncryptionError,
    #[error("Unsupported algorithm")]
    UnsupportedAlgorithm,
    #[error("Invalid key")]
    InvalidKey,
    #[error("Crypto library error")]
    CryptoError,
}

/// Generates a keypair for the given KEM algorithm.
///
/// Returns a tuple containing the public and private keys respectively.
pub fn generate_keypair(algo: KemAlgorithm) -> Result<(PublicKey, PrivateKey), Error> {
    clear_stack_on_return(CLEAR_STACK_PAGES, || match algo {
        KemAlgorithm::DhkemX25519HkdfSha256 => {
            let (pk, sk) = x25519::generate_keypair();
            Ok((PublicKey::X25519(pk), PrivateKey::X25519(sk)))
        }
        _ => Err(Error::UnsupportedAlgorithm),
    })
}

#[cfg(any(test, feature = "test-utils"))]
/// Helper for HPKE LabeledExtract
fn labeled_extract(suite_id: &[u8], salt: hkdf::Salt, label: &[u8], ikm: &[u8]) -> hkdf::Prk {
    let mut labeled_ikm = Vec::with_capacity(7 + suite_id.len() + label.len() + ikm.len());
    labeled_ikm.extend_from_slice(b"HPKE-v1");
    labeled_ikm.extend_from_slice(suite_id);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);
    hkdf::HkdfSha256::extract(&labeled_ikm, salt)
}

#[cfg(any(test, feature = "test-utils"))]
/// Helper for HPKE LabeledExpand
fn labeled_expand(
    suite_id: &[u8],
    prk: &hkdf::Prk,
    label: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    let mut labeled_info = Vec::with_capacity(2 + 7 + suite_id.len() + label.len() + info.len());
    labeled_info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    labeled_info.extend_from_slice(b"HPKE-v1");
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);
    prk.expand_into(&labeled_info, out)
        .map_err(|_| Error::CryptoError)
}

#[cfg(any(test, feature = "test-utils"))]
/// [Test-Only] BoringSSL lacks a public API to initialize a RecipientContext directly from a shared-secret.
/// Manual HPKE open implementation to decrypt a ciphertext using HPKE with a pre-calculated shared secret.
pub fn hpke_open_with_shared_secret(
    shared_secret: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
    algo: &HpkeAlgorithm,
) -> Result<Vec<u8>, Error> {
    clear_stack_on_return(2, || {
        let kem = KemAlgorithm::try_from(algo.kem).map_err(|_| Error::UnsupportedAlgorithm)?;
        let kdf = KdfAlgorithm::try_from(algo.kdf).map_err(|_| Error::UnsupportedAlgorithm)?;
        let aead_algo =
            AeadAlgorithm::try_from(algo.aead).map_err(|_| Error::UnsupportedAlgorithm)?;

        if kem != KemAlgorithm::DhkemX25519HkdfSha256
            || kdf != KdfAlgorithm::HkdfSha256
            || aead_algo != AeadAlgorithm::Aes256Gcm
        {
            return Err(Error::UnsupportedAlgorithm);
        }

        // suite_id = "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)
        let suite_id = [b'H', b'P', b'K', b'E', 0, 0x20, 0, 0x01, 0, 0x02];
        let info = b""; // Default info used in hpke_seal/open

        // KeySchedule(mode_base, shared_secret, info, psk, psk_id)
        // 1. psk_id_hash = LabeledExtract("", "psk_id_hash", psk_id)
        let psk_id_hash_prk = labeled_extract(&suite_id, hkdf::Salt::None, b"psk_id_hash", b"");
        let psk_id_hash = psk_id_hash_prk.as_bytes();

        // 2. info_hash = LabeledExtract("", "info_hash", info)
        let info_hash_prk = labeled_extract(&suite_id, hkdf::Salt::None, b"info_hash", info);
        let info_hash = info_hash_prk.as_bytes();

        // 3. key_schedule_context = mode || psk_id_hash || info_hash
        let mut key_schedule_context = Vec::with_capacity(1 + psk_id_hash.len() + info_hash.len());
        key_schedule_context.push(0); // mode_base
        key_schedule_context.extend_from_slice(psk_id_hash);
        key_schedule_context.extend_from_slice(info_hash);

        // 4. secret = LabeledExtract(shared_secret, "secret", psk)
        let secret_prk = labeled_extract(
            &suite_id,
            hkdf::Salt::NonEmpty(shared_secret),
            b"secret",
            b"",
        );

        // 5. key = LabeledExpand(secret, "key", key_schedule_context, Nk)
        let mut key = [0u8; 32];
        labeled_expand(
            &suite_id,
            &secret_prk,
            b"key",
            &key_schedule_context,
            &mut key,
        )?;

        // 6. nonce = LabeledExpand(secret, "base_nonce", key_schedule_context, Nn)
        let mut nonce = [0u8; 12];
        labeled_expand(
            &suite_id,
            &secret_prk,
            b"base_nonce",
            &key_schedule_context,
            &mut nonce,
        )?;

        // 7. AEAD Open
        let aead = aead::Aes256Gcm::new(&key);
        aead.open(&nonce, ciphertext, aad)
            .ok_or(Error::HpkeDecryptionError)
    })
}

/// Decapsulates the shared secret from an encapsulated key using the specified private key.
///
/// Returns the decapsulated shared secret as a `SecretBox`.
pub fn decaps(priv_key: &PrivateKey, enc: &[u8]) -> Result<SecretBox, Error> {
    clear_stack_on_return(CLEAR_STACK_PAGES, || priv_key.decaps_internal(enc))
}

/// Decrypts a ciphertext using HPKE (Hybrid Public Key Encryption).
///
/// Returns the decrypted plaintext as a `SecretBox`.
pub fn hpke_open(
    priv_key: &PrivateKey,
    enc: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
    algo: &HpkeAlgorithm,
) -> Result<SecretBox, Error> {
    clear_stack_on_return(CLEAR_STACK_PAGES, || {
        priv_key.hpke_open_internal(enc, ciphertext, aad, algo)
    })
}

/// Encrypts a plaintext using HPKE (Hybrid Public Key Encryption).
///
/// Returns a tuple containing the encapsulated key and the ciphertext.
pub fn hpke_seal(
    pub_key: &PublicKey,
    plaintext: &SecretBox,
    aad: &[u8],
    algo: &HpkeAlgorithm,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    clear_stack_on_return(CLEAR_STACK_PAGES, || {
        pub_key.hpke_seal_internal(plaintext, aad, algo)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::{AeadAlgorithm, KdfAlgorithm};
    use bssl_crypto::hpke;

    #[test]
    fn test_decaps_wrapper() {
        let kem_algo = KemAlgorithm::DhkemX25519HkdfSha256;
        let (pk_r, sk_r) = generate_keypair(kem_algo).expect("KEM generation failed");

        let hpke_kem = hpke::Kem::X25519HkdfSha256;
        let hpke_kdf = hpke::Kdf::HkdfSha256;
        let hpke_aead = hpke::Aead::Aes256Gcm;
        let params = hpke::Params::new(hpke_kem, hpke_kdf, hpke_aead);

        let (_sender_ctx, enc) = hpke::SenderContext::new(&params, pk_r.as_bytes(), b"")
            .expect("HPKE setup sender failed");

        let result = decaps(&sk_r, &enc).expect("Decaps wrapper failed");
        assert_eq!(result.as_slice().len(), 32);
    }

    #[test]
    fn test_decaps_unsupported() {
        let kem_algo = KemAlgorithm::DhkemX25519HkdfSha256;
        let (_pk_r, sk_r) = generate_keypair(kem_algo).expect("KEM generation failed");

        let enc = [0u8; 32];
        let algo = HpkeAlgorithm {
            kem: KemAlgorithm::Unspecified as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        let result = hpke_open(&sk_r, &enc, &[], &[], &algo);
        assert!(matches!(result, Err(Error::UnsupportedAlgorithm)));
    }

    #[test]
    fn test_hpke_open_success() {
        let hpke_algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        let kem_algo = KemAlgorithm::DhkemX25519HkdfSha256;

        let (pk_r, sk_r) = generate_keypair(kem_algo).expect("HPKE generation failed");

        let pt = b"hello world";
        let aad = b"additional data";
        let info = b"";

        let hpke_kem = hpke::Kem::X25519HkdfSha256;
        let hpke_kdf = hpke::Kdf::HkdfSha256;
        let hpke_aead = hpke::Aead::Aes256Gcm;
        let params = hpke::Params::new(hpke_kem, hpke_kdf, hpke_aead);

        let (mut sender_ctx, enc) = hpke::SenderContext::new(&params, pk_r.as_bytes(), info)
            .expect("HPKE setup sender failed");
        let ciphertext = sender_ctx.seal(pt, aad);

        let decrypted =
            hpke_open(&sk_r, &enc, &ciphertext, aad, &hpke_algo).expect("Decryption failed");

        assert_eq!(decrypted.as_slice(), pt);
    }

    #[test]
    fn test_hpke_open_failure() {
        let hpke_algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        let kem_algo = KemAlgorithm::DhkemX25519HkdfSha256;

        let (pk_r, sk_r) = generate_keypair(kem_algo).expect("HPKE generation failed");

        let pt = b"hello world";
        let aad = b"additional data";
        let info = b"";

        let hpke_kem = hpke::Kem::X25519HkdfSha256;
        let hpke_kdf = hpke::Kdf::HkdfSha256;
        let hpke_aead = hpke::Aead::Aes256Gcm;
        let params = hpke::Params::new(hpke_kem, hpke_kdf, hpke_aead);

        let (mut sender_ctx, enc) = hpke::SenderContext::new(&params, pk_r.as_bytes(), info)
            .expect("HPKE setup sender failed");
        let mut ciphertext = sender_ctx.seal(pt, aad);

        // Tamper with ciphertext
        if let Some(byte) = ciphertext.get_mut(0) {
            *byte ^= 1;
        }

        let result = hpke_open(&sk_r, &enc, &ciphertext, aad, &hpke_algo);
        assert!(matches!(result, Err(Error::HpkeDecryptionError)));
    }

    #[test]
    fn test_hpke_bad_aad() {
        let hpke_algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };

        let kem_algo = KemAlgorithm::DhkemX25519HkdfSha256;

        let (pk_r, sk_r) = generate_keypair(kem_algo).expect("HPKE generation failed");

        let pt = b"hello world";
        let aad = b"foo";
        let info = b"";

        let hpke_kem = hpke::Kem::X25519HkdfSha256;
        let hpke_kdf = hpke::Kdf::HkdfSha256;
        let hpke_aead = hpke::Aead::Aes256Gcm;
        let params = hpke::Params::new(hpke_kem, hpke_kdf, hpke_aead);

        let (mut sender_ctx, enc) = hpke::SenderContext::new(&params, pk_r.as_bytes(), info)
            .expect("HPKE setup sender failed");
        let ciphertext = sender_ctx.seal(pt, aad);

        // Tamper with aad
        let tampered_aad = b"bar";

        let result = hpke_open(&sk_r, &enc, &ciphertext, tampered_aad, &hpke_algo);
        assert!(matches!(result, Err(Error::HpkeDecryptionError)));
    }

    #[test]
    fn test_hpke_seal_success() {
        let hpke_algo = HpkeAlgorithm {
            kem: KemAlgorithm::DhkemX25519HkdfSha256 as i32,
            kdf: KdfAlgorithm::HkdfSha256 as i32,
            aead: AeadAlgorithm::Aes256Gcm as i32,
        };
        let kem_algo = KemAlgorithm::DhkemX25519HkdfSha256;

        let (pk_r, sk_r) = generate_keypair(kem_algo).expect("HPKE generation failed");

        let pt = SecretBox::new(b"hello world".to_vec());
        let aad = b"additional data";

        // Seal
        let (enc, ciphertext) = hpke_seal(&pk_r, &pt, aad, &hpke_algo).expect("HPKE seal failed");

        // Decrypt to verify
        let decrypted =
            hpke_open(&sk_r, &enc, &ciphertext, aad, &hpke_algo).expect("Decryption failed");
        assert_eq!(decrypted.as_slice(), pt.as_slice());
    }

    #[test]
    fn test_generate_kem_success() {
        let algo = KemAlgorithm::DhkemX25519HkdfSha256;
        let (pub_key, _priv_key) = generate_keypair(algo).expect("KEM generation failed");
        assert_eq!(pub_key.as_bytes().len(), 32);
    }

    #[test]
    fn test_generate_hpke_success() {
        let algo = KemAlgorithm::DhkemX25519HkdfSha256;

        let (pub_key, _priv_key) = generate_keypair(algo).expect("HPKE generation failed");
        assert_eq!(pub_key.as_bytes().len(), 32);
    }

    #[test]
    fn test_generate_hpke_unsupported() {
        let algo = KemAlgorithm::Unspecified;

        let result = generate_keypair(algo);
        assert!(matches!(result, Err(Error::UnsupportedAlgorithm)));
    }
}
