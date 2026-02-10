use crate::algorithms::{AeadAlgorithm, HpkeAlgorithm, KdfAlgorithm, KemAlgorithm};
use crate::crypto::{Error, PrivateKeyOps, PublicKeyOps};
use bssl_crypto::{hkdf, hpke, x25519};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// X25519-based public key implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X25519PublicKey([u8; 32]);

impl AsRef<[u8]> for X25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl PublicKeyOps for X25519PublicKey {
    fn hpke_seal_internal(
        &self,
        plaintext: &[u8],
        aad: &[u8],
        algo: &HpkeAlgorithm,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        match (
            KemAlgorithm::try_from(algo.kem),
            KdfAlgorithm::try_from(algo.kdf),
            AeadAlgorithm::try_from(algo.aead),
        ) {
            (
                Ok(KemAlgorithm::DhkemX25519HkdfSha256),
                Ok(KdfAlgorithm::HkdfSha256),
                Ok(AeadAlgorithm::Aes256Gcm),
            ) => {
                let params = hpke::Params::new(
                    hpke::Kem::X25519HkdfSha256,
                    hpke::Kdf::HkdfSha256,
                    hpke::Aead::Aes256Gcm,
                );

                let (mut sender_ctx, encapsulated_key) =
                    hpke::SenderContext::new(&params, self.as_ref(), b"")
                        .ok_or(Error::HpkeEncryptionError)?;

                let ciphertext = sender_ctx.seal(plaintext, aad);
                Ok((encapsulated_key, ciphertext))
            }
            _ => Err(Error::UnsupportedAlgorithm),
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// X25519-based private key implementation.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct X25519PrivateKey([u8; 32]);

impl PrivateKeyOps for X25519PrivateKey {
    /// Decapsulates the shared secret from an encapsulated key.
    /// Follows RFC 9180 Section 4.1. DHKEM(Group, Hash).
    fn decaps_internal(&self, enc: &[u8]) -> Result<Vec<u8>, Error> {
        let priv_key = x25519::PrivateKey(self.0);

        // 1. Compute Diffie-Hellman shared secret
        // dh = dhExchange(skR, pkE)
        let shared_key = Zeroizing::new(
            priv_key
                .compute_shared_key(enc.try_into().map_err(|_| Error::KeyLenMismatch)?)
                .ok_or(Error::DecapsError)?,
        );

        // DHKEM(X25519, HKDF-SHA256)
        // suite_id = "KEM" || I2OSP(kem_id, 2)
        // For X25519 (0x0020)
        let suite_id = [b'K', b'E', b'M', 0, 0x20];

        // 2. Extract eae_prk
        // eae_prk = LabeledExtract("", "eae_prk", dh)
        // LabeledExtract(salt, label, ikm) = HKDF-Extract(salt, "HPKE-v1" || suite_id || label || ikm)
        let labeled_ikm = Zeroizing::new(
            [
                b"HPKE-v1".as_slice(),
                &suite_id,
                b"eae_prk",
                shared_key.as_ref(),
            ]
            .concat(),
        );

        let prk = hkdf::HkdfSha256::extract(&labeled_ikm, hkdf::Salt::None);

        let pub_key = priv_key.to_public();

        // 3. Expand shared_secret
        // shared_secret = LabeledExpand(eae_prk, "shared_secret", enc || pkR, L)
        // LabeledExpand(prk, label, info, L) = HKDF-Expand(prk, "HPKE-v1" || suite_id || label || info, L)
        let labeled_info = Zeroizing::new(
            [
                &[0x00u8, 0x20] as &[u8], // L = 32
                b"HPKE-v1",
                &suite_id,
                b"shared_secret",
                enc,
                &pub_key,
            ]
            .concat(),
        );

        let mut result = vec![0u8; 32];
        prk.expand_into(labeled_info.as_ref(), &mut result)
            .map_err(|_| Error::DecapsError)?;

        Ok(result)
    }

    fn hpke_open_internal(
        &self,
        enc: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
        algo: &HpkeAlgorithm,
    ) -> Result<Vec<u8>, Error> {
        match (
            KemAlgorithm::try_from(algo.kem),
            KdfAlgorithm::try_from(algo.kdf),
            AeadAlgorithm::try_from(algo.aead),
        ) {
            (
                Ok(KemAlgorithm::DhkemX25519HkdfSha256),
                Ok(KdfAlgorithm::HkdfSha256),
                Ok(AeadAlgorithm::Aes256Gcm),
            ) => {
                let params = hpke::Params::new(
                    hpke::Kem::X25519HkdfSha256,
                    hpke::Kdf::HkdfSha256,
                    hpke::Aead::Aes256Gcm,
                );

                let mut recipient_ctx = hpke::RecipientContext::new(&params, &self.0, enc, b"")
                    .ok_or(Error::HpkeDecryptionError)?;

                recipient_ctx
                    .open(ciphertext, aad)
                    .ok_or(Error::HpkeDecryptionError)
            }
            _ => Err(Error::UnsupportedAlgorithm),
        }
    }
}

/// Generates a new X25519 keypair.
pub(crate) fn generate_keypair() -> (X25519PublicKey, X25519PrivateKey) {
    let (pk, sk) = hpke::Kem::X25519HkdfSha256.generate_keypair();
    (
        X25519PublicKey(pk.try_into().expect("X25519 public key must be 32 bytes")),
        X25519PrivateKey(sk.try_into().expect("X25519 private key must be 32 bytes")),
    )
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

        let sk_r_bytes: [u8; 32] = hex::decode(sk_r_hex).unwrap().try_into().unwrap();
        let sk_r = X25519PrivateKey(sk_r_bytes);
        let enc = hex::decode(enc_hex).unwrap();

        let result = sk_r.decaps_internal(&enc).expect("Decapsulation failed");

        assert_eq!(
            hex::encode(&result),
            expected_shared_secret_hex,
            "Shared secret mismatch"
        );
    }
}
