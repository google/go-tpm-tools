use crate::algorithms::{HpkeAlgorithm, KemAlgorithm};
pub mod secret_box;
use crate::crypto::secret_box::SecretBox;
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

impl PrivateKey {
    /// Consumes the `PrivateKey` and returns the inner `SecretBox`.
    pub fn into_secret(self) -> SecretBox {
        match self {
            PrivateKey::X25519(sk) => sk.into_secret(),
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
