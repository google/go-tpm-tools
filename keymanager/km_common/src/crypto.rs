use crate::algorithms::{AeadAlgorithm, HpkeAlgorithm, KdfAlgorithm, KemAlgorithm};
use bssl_crypto::{hkdf, hpke, x25519};
use clear_on_drop::clear_stack_on_return;
use thiserror::Error;

const CLEAR_STACK_PAGES: usize = 2;

/// A wrapper around a public key to avoid mixing with private keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(pub Vec<u8>);

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for PublicKey {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

/// A wrapper around a private key to avoid mixing with public keys.
#[derive(PartialEq, Eq)]
pub struct PrivateKey(pub Vec<u8>);

impl AsRef<[u8]> for PrivateKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for PrivateKey {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
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
pub fn generate_keypair(algo: KemAlgorithm) -> Result<(PublicKey, PrivateKey), Error> {
    clear_stack_on_return(CLEAR_STACK_PAGES, || match algo {
        KemAlgorithm::DhkemX25519HkdfSha256 => {
            let (pk, sk) = hpke::Kem::X25519HkdfSha256.generate_keypair();
            Ok((PublicKey(pk), PrivateKey(sk)))
        }
        _ => Err(Error::UnsupportedAlgorithm),
    })
}

/// BoringSSL lacks a DHKEM decap API which can perform and DH + KDF operation to generate a shared secret key.
/// Manual implementation to decapsulate a shared secret from an encapsulated key using an X25519 private key.
pub fn decaps_x25519(priv_key: &PrivateKey, enc: &[u8]) -> Result<Vec<u8>, Error> {
    clear_stack_on_return(CLEAR_STACK_PAGES, || {
        let priv_key = x25519::PrivateKey(
            priv_key
                .as_ref()
                .try_into()
                .map_err(|_| Error::KeyLenMismatch)?,
        );

        // Compute Diffie-Hellman shared secret
        let shared_key = priv_key
            .compute_shared_key(enc.try_into().map_err(|_| Error::KeyLenMismatch)?)
            .ok_or(Error::DecapsError)?;

        // DHKEM(X25519, HKDF-SHA256)
        // LabeledExtract(salt, label, ikm) = HKDF-Extract(salt, "HPKE-v1" || suite_id || label || ikm)
        // suite_id = "KEM" || I2OSP(kem_id, 2)
        let suite_id = [b'K', b'E', b'M', 0, 0x20];

        // Extract eae_prk
        // labeled_ikm = "HPKE-v1" || suite_id || "eae_prk" || shared_key
        let labeled_ikm = [b"HPKE-v1".as_slice(), &suite_id, b"eae_prk", &shared_key].concat();

        let prk = hkdf::HkdfSha256::extract(&labeled_ikm, hkdf::Salt::None);

        let pub_key = priv_key.to_public();

        // Expand shared_secret
        // labeled_info = I2OSP(L, 2) || "HPKE-v1" || suite_id || "shared_secret" || enc || pkR
        let labeled_info = [
            &[0x00u8, 0x20] as &[u8], // L = 32
            b"HPKE-v1",
            &suite_id,
            b"shared_secret",
            enc,
            &pub_key,
        ]
        .concat();

        let mut result = vec![0u8; 32];
        prk.expand_into(&labeled_info, &mut result)
            .map_err(|_| Error::DecapsError)?;

        Ok(result)
    })
}

/// Decapsulates the shared secret from an encapsulated key using the specified KEM algorithm.
pub fn decaps(priv_key: &PrivateKey, enc: &[u8], algo: KemAlgorithm) -> Result<Vec<u8>, Error> {
    clear_stack_on_return(CLEAR_STACK_PAGES, || match algo {
        KemAlgorithm::DhkemX25519HkdfSha256 => decaps_x25519(priv_key, enc),
        _ => Err(Error::UnsupportedAlgorithm),
    })
}

/// Decrypts a ciphertext using HPKE (Hybrid Public Key Encryption).
pub fn hpke_open(
    priv_key: &PrivateKey,
    enc: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
    algo: &HpkeAlgorithm,
) -> Result<Vec<u8>, Error> {
    clear_stack_on_return(CLEAR_STACK_PAGES, || {
        let kem = KemAlgorithm::try_from(algo.kem).map_err(|_| Error::UnsupportedAlgorithm)?;
        let kdf = KdfAlgorithm::try_from(algo.kdf).map_err(|_| Error::UnsupportedAlgorithm)?;
        let aead = AeadAlgorithm::try_from(algo.aead).map_err(|_| Error::UnsupportedAlgorithm)?;

        match (kem, kdf, aead) {
            (
                KemAlgorithm::DhkemX25519HkdfSha256,
                KdfAlgorithm::HkdfSha256,
                AeadAlgorithm::Aes256Gcm,
            ) => {
                let params = hpke::Params::new(
                    hpke::Kem::X25519HkdfSha256,
                    hpke::Kdf::HkdfSha256,
                    hpke::Aead::Aes256Gcm,
                );

                let mut recipient_ctx =
                    hpke::RecipientContext::new(&params, priv_key.as_ref(), enc, b"")
                        .ok_or(Error::HpkeDecryptionError)?;

                recipient_ctx
                    .open(ciphertext, aad)
                    .ok_or(Error::HpkeDecryptionError)
            }
            _ => Err(Error::UnsupportedAlgorithm),
        }
    })
}

/// Encrypts a plaintext using HPKE (Hybrid Public Key Encryption).
///
/// Returns a tuple containing the encapsulated key and the ciphertext.
pub fn hpke_seal(
    pub_key: &PublicKey,
    plaintext: &[u8],
    aad: &[u8],
    algo: &HpkeAlgorithm,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    clear_stack_on_return(CLEAR_STACK_PAGES, || {
        let kem = KemAlgorithm::try_from(algo.kem).map_err(|_| Error::UnsupportedAlgorithm)?;
        let kdf = KdfAlgorithm::try_from(algo.kdf).map_err(|_| Error::UnsupportedAlgorithm)?;
        let aead = AeadAlgorithm::try_from(algo.aead).map_err(|_| Error::UnsupportedAlgorithm)?;

        match (kem, kdf, aead) {
            (
                KemAlgorithm::DhkemX25519HkdfSha256,
                KdfAlgorithm::HkdfSha256,
                AeadAlgorithm::Aes256Gcm,
            ) => {
                let params = hpke::Params::new(
                    hpke::Kem::X25519HkdfSha256,
                    hpke::Kdf::HkdfSha256,
                    hpke::Aead::Aes256Gcm,
                );

                let (mut sender_ctx, encapsulated_key) =
                    hpke::SenderContext::new(&params, pub_key.as_ref(), b"")
                        .ok_or(Error::HpkeEncryptionError)?;

                let ciphertext = sender_ctx.seal(plaintext, aad);
                Ok((encapsulated_key, ciphertext))
            }
            _ => Err(Error::UnsupportedAlgorithm),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_decaps_x25519_clamped_vector() {
        // Since BoringSSL X25519 always clamps the private key, we use vectors that
        // are consistent with clamping.
        // Input private key (clamped internally by BoringSSL):
        let sk_r_hex = "468c86c75053df4d0925e01f5446700e57288f3316c5b610c3b9b94090b8f2cb";
        let enc_hex = "1b2767097950294d300c2830366c3c58853c83a736466336e392576b9762194d";

        // This is what we get when we run with clamping:
        let expected_shared_secret_hex =
            "b1e179eefbcdfe490a1929c3c6e5de6d98f3ed4463b6d94627390119610baa83";

        let sk_r = PrivateKey(hex::decode(sk_r_hex).unwrap());
        let enc = hex::decode(enc_hex).unwrap();

        let result = decaps_x25519(&sk_r, &enc).expect("Decapsulation failed");

        assert_eq!(
            hex::encode(&result),
            expected_shared_secret_hex,
            "Shared secret mismatch"
        );
    }

    #[test]
    fn test_decaps_wrapper() {
        let kem_algo = KemAlgorithm::DhkemX25519HkdfSha256;
        let (pk_r, sk_r) = generate_keypair(kem_algo).expect("KEM generation failed");

        let hpke_kem = hpke::Kem::X25519HkdfSha256;
        let hpke_kdf = hpke::Kdf::HkdfSha256;
        let hpke_aead = hpke::Aead::Aes256Gcm;
        let params = hpke::Params::new(hpke_kem, hpke_kdf, hpke_aead);

        let (_sender_ctx, enc) =
            hpke::SenderContext::new(&params, &pk_r.0, b"").expect("HPKE setup sender failed");

        let result = decaps(&sk_r, &enc, kem_algo).expect("Decaps wrapper failed");
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_decaps_unsupported() {
        let sk_r = PrivateKey(vec![0u8; 32]);
        let enc = [0u8; 32];
        let algo = KemAlgorithm::Unspecified;

        let result = decaps(&sk_r, &enc, algo);
        assert!(matches!(result, Err(Error::UnsupportedAlgorithm)));
    }

    #[test]
    fn test_decaps_invalid_lengths() {
        let algo = KemAlgorithm::DhkemX25519HkdfSha256;

        // Short private key
        assert!(matches!(
            decaps(&PrivateKey(vec![0u8; 31]), &[0u8; 32], algo),
            Err(Error::KeyLenMismatch)
        ));

        // Short encapsulated key
        assert!(matches!(
            decaps(&PrivateKey(vec![0u8; 32]), &[0u8; 31], algo),
            Err(Error::KeyLenMismatch)
        ));
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

        let (mut sender_ctx, enc) =
            hpke::SenderContext::new(&params, &pk_r.0, info).expect("HPKE setup sender failed");
        let ciphertext = sender_ctx.seal(pt, aad);

        let decrypted =
            hpke_open(&sk_r, &enc, &ciphertext, aad, &hpke_algo).expect("Decryption failed");

        assert_eq!(decrypted, pt);
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

        let (mut sender_ctx, enc) =
            hpke::SenderContext::new(&params, &pk_r.0, info).expect("HPKE setup sender failed");
        let mut ciphertext = sender_ctx.seal(pt, aad);

        // Tamper with ciphertext
        if let Some(byte) = ciphertext.get_mut(0) {
            *byte ^= 1;
        }

        let result = hpke_open(&sk_r, &enc, &ciphertext, aad, &hpke_algo);
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

        let pt = b"hello world";
        let aad = b"additional data";

        // Seal
        let (enc, ciphertext) = hpke_seal(&pk_r, pt, aad, &hpke_algo).expect("HPKE seal failed");

        // Decrypt to verify
        let decrypted =
            hpke_open(&sk_r, &enc, &ciphertext, aad, &hpke_algo).expect("Decryption failed");
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_generate_kem_success() {
        let algo = KemAlgorithm::DhkemX25519HkdfSha256;
        let (pub_key, priv_key) = generate_keypair(algo).expect("KEM generation failed");
        assert_eq!(pub_key.0.len(), 32);
        assert_eq!(priv_key.0.len(), 32);
    }

    #[test]
    fn test_generate_hpke_success() {
        let algo = KemAlgorithm::DhkemX25519HkdfSha256;

        let (pub_key, priv_key) = generate_keypair(algo).expect("HPKE generation failed");
        assert_eq!(pub_key.0.len(), 32);
        assert_eq!(priv_key.0.len(), 32);
    }

    #[test]
    fn test_generate_hpke_unsupported() {
        let algo = KemAlgorithm::Unspecified;

        let result = generate_keypair(algo);
        assert!(matches!(result, Err(Error::UnsupportedAlgorithm)));
    }
}
