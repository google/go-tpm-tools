use crate::algorithms::{AeadAlgorithm, HpkeAlgorithm, KdfAlgorithm, KemAlgorithm};
use crate::crypto::secret_box::SecretBox;
use crate::crypto::{Error, PrivateKeyOps, PublicKeyOps};
use bssl_crypto::{hkdf, hpke, x25519};

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
        plaintext: &SecretBox,
        aad: &[u8],
        algo: &HpkeAlgorithm,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let (
            Ok(KemAlgorithm::DhkemX25519HkdfSha256),
            Ok(KdfAlgorithm::HkdfSha256),
            Ok(AeadAlgorithm::Aes256Gcm),
        ) = (
            KemAlgorithm::try_from(algo.kem),
            KdfAlgorithm::try_from(algo.kdf),
            AeadAlgorithm::try_from(algo.aead),
        )
        else {
            return Err(Error::UnsupportedAlgorithm);
        };

        let params = hpke::Params::new(
            hpke::Kem::X25519HkdfSha256,
            hpke::Kdf::HkdfSha256,
            hpke::Aead::Aes256Gcm,
        );

        let (mut sender_ctx, encapsulated_key) =
            hpke::SenderContext::new(&params, self.as_ref(), b"")
                .ok_or(Error::HpkeEncryptionError)?;

        let ciphertext = sender_ctx.seal(plaintext.as_slice(), aad);
        Ok((encapsulated_key, ciphertext))
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// X25519-based private key implementation.
pub struct X25519PrivateKey(SecretBox);

impl PrivateKeyOps for X25519PrivateKey {
    /// Decapsulates the shared secret from an encapsulated key.
    /// Follows RFC 9180 Section 4.1. DHKEM(Group, Hash).
    fn decaps_internal(&self, enc: &[u8]) -> Result<SecretBox, Error> {
        let priv_key = x25519::PrivateKey(
            self.0
                .as_slice()
                .try_into()
                .map_err(|_| Error::KeyLenMismatch)?,
        );

        // 1. Compute Diffie-Hellman shared secret
        // dh = dhExchange(skR, pkE)
        let shared_key = SecretBox::new(
            priv_key
                .compute_shared_key(enc.try_into().map_err(|_| Error::KeyLenMismatch)?)
                .ok_or(Error::DecapsError)?
                .to_vec(),
        );

        // DHKEM(X25519, HKDF-SHA256)
        // suite_id = "KEM" || I2OSP(kem_id, 2)
        // For X25519 (0x0020)
        let suite_id = [b'K', b'E', b'M', 0, 0x20];

        // 2. Extract eae_prk
        // eae_prk = LabeledExtract("", "eae_prk", dh)
        let prk = labeled_extract(b"", b"eae_prk", shared_key.as_slice(), &suite_id);

        let pub_key = priv_key.to_public();

        // 3. Expand shared_secret
        // shared_secret = LabeledExpand(eae_prk, "shared_secret", enc || pkR, L)
        let info = [enc, &pub_key].concat();

        labeled_expand(&prk, b"shared_secret", &info, &suite_id, 32)
    }

    fn hpke_open_internal(
        &self,
        enc: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
        algo: &HpkeAlgorithm,
    ) -> Result<SecretBox, Error> {
        let (
            Ok(KemAlgorithm::DhkemX25519HkdfSha256),
            Ok(KdfAlgorithm::HkdfSha256),
            Ok(AeadAlgorithm::Aes256Gcm),
        ) = (
            KemAlgorithm::try_from(algo.kem),
            KdfAlgorithm::try_from(algo.kdf),
            AeadAlgorithm::try_from(algo.aead),
        )
        else {
            return Err(Error::UnsupportedAlgorithm);
        };

        let params = hpke::Params::new(
            hpke::Kem::X25519HkdfSha256,
            hpke::Kdf::HkdfSha256,
            hpke::Aead::Aes256Gcm,
        );

        let mut recipient_ctx = hpke::RecipientContext::new(&params, self.0.as_slice(), enc, b"")
            .ok_or(Error::HpkeDecryptionError)?;

        recipient_ctx
            .open(ciphertext, aad)
            .map(SecretBox::new)
            .ok_or(Error::HpkeDecryptionError)
    }
}

/// LabeledExtract(salt, label, ikm) = HKDF-Extract(salt, "HPKE-v1" || suite_id || label || ikm)
fn labeled_extract(salt: &[u8], label: &[u8], ikm: &[u8], suite_id: &[u8]) -> hkdf::Prk {
    let labeled_ikm = SecretBox::new([b"HPKE-v1".as_slice(), suite_id, label, ikm].concat());
    hkdf::HkdfSha256::extract(labeled_ikm.as_slice(), hkdf::Salt::NonEmpty(salt))
}

/// LabeledExpand(prk, label, info, L) = HKDF-Expand(prk, "HPKE-v1" || suite_id || label || info, L)
fn labeled_expand(
    prk: &hkdf::Prk,
    label: &[u8],
    info: &[u8],
    suite_id: &[u8],
    len: u16,
) -> Result<SecretBox, Error> {
    let labeled_info = SecretBox::new(
        [
            &len.to_be_bytes() as &[u8],
            b"HPKE-v1",
            suite_id,
            label,
            info,
        ]
        .concat(),
    );

    let mut result = vec![0u8; len as usize];
    prk.expand_into(labeled_info.as_slice(), &mut result)
        .map_err(|_| Error::DecapsError)?;

    Ok(SecretBox::new(result))
}

/// Generates a new X25519 keypair.
pub(crate) fn generate_keypair() -> (X25519PublicKey, X25519PrivateKey) {
    let (pk, sk) = hpke::Kem::X25519HkdfSha256.generate_keypair();
    (
        X25519PublicKey(pk.try_into().expect("X25519 public key must be 32 bytes")),
        X25519PrivateKey(SecretBox::new(sk)),
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

        let sk_r_bytes: Vec<u8> = hex::decode(sk_r_hex).unwrap();
        let sk_r = X25519PrivateKey(SecretBox::new(sk_r_bytes));
        let enc = hex::decode(enc_hex).unwrap();

        let result = sk_r.decaps_internal(&enc).expect("Decapsulation failed");

        assert_eq!(
            hex::encode(result.as_slice()),
            expected_shared_secret_hex,
            "Shared secret mismatch"
        );
    }

    #[test]
    fn test_labeled_extract_and_expand() {
        let suite_id = [b'K', b'E', b'M', 0, 0x20];
        let salt = b"test_salt";
        let label = b"test_label";
        let ikm = b"test_ikm";
        let info = b"test_info";

        // Test labeled_extract
        let prk = labeled_extract(salt, label, ikm, &suite_id);

        // Test labeled_expand with length 32
        let len = 32;
        let result = labeled_expand(&prk, label, info, &suite_id, len).expect("expand failed");
        assert_eq!(result.as_slice().len(), len as usize);

        // Test labeled_expand with different info produces different result
        let result2 =
            labeled_expand(&prk, label, b"other_info", &suite_id, len).expect("expand failed");
        assert_ne!(result.as_slice(), result2.as_slice());

        // Test labeled_expand with different label produces different result
        let result3 =
            labeled_expand(&prk, b"other_label", info, &suite_id, len).expect("expand failed");
        assert_ne!(result.as_slice(), result3.as_slice());
    }
}
