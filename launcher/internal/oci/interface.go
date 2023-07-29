// Package oci contains functionalities to interact with OCI image signatures.
// https://github.com/opencontainers/image-spec/tree/main#readme.
package oci

import (
	"go.uber.org/multierr"
)

// SigningAlgorithm is a specific type for string constants used for sigature signing and verification.
type SigningAlgorithm string

const (
	// RSASSAPSS2048SHA256 is RSASSA-PSS 2048 bit key with a SHA256 digest supported for cosign sign.
	RSASSAPSS2048SHA256 SigningAlgorithm = "RSASSA_PSS_2048_SHA256"
	// RSASSAPSS3072SHA256 is RSASSA-PSS 3072 bit key with a SHA256 digest supported for cosign sign.
	RSASSAPSS3072SHA256 SigningAlgorithm = "RSASSA_PSS_3072_SHA256"
	// RSASSAPSS4096SHA256 is RSASSA-PSS 4096 bit key with a SHA256 digest supported for cosign sign.
	RSASSAPSS4096SHA256 SigningAlgorithm = "RSASSA_PSS_4096_SHA256"
	// RSASSAPKCS1V152048SHA256 is RSASSA-PKCS1 v1.5 2048 bit key with a SHA256 digest supported for cosign sign.
	RSASSAPKCS1V152048SHA256 SigningAlgorithm = "RSASSA_PKCS1V15_2048_SHA256"
	// RSASSAPKCS1V153072SHA256 is RSASSA-PKCS1 v1.5 3072 bit key with a SHA256 digest supported for cosign sign.
	RSASSAPKCS1V153072SHA256 SigningAlgorithm = "RSASSA_PKCS1V15_3072_SHA256"
	// RSASSAPKCS1V154096SHA256 is RSASSA-PKCS1 v1.5 4096 bit key with a SHA256 digest supported for cosign sign.
	RSASSAPKCS1V154096SHA256 SigningAlgorithm = "RSASSA_PKCS1V15_4096_SHA256"
	// ECDSAP256SHA256 is ECDSA on the P-256 Curve with a SHA256 digest supported for cosign sign.
	ECDSAP256SHA256 SigningAlgorithm = "ECDSA_P256_SHA256"
)

// Signature represents a single OCI image signature.
type Signature interface {
	// Payload returns the blob data associated with a signature uploaded to an OCI registry.
	Payload() ([]byte, error)

	// Base64Encoded returns the base64-encoded signature of the signed payload.
	Base64Encoded() (string, error)

	// PublicKey returns a public key in the format of PEM-encoded byte slice.
	PublicKey() ([]byte, error)

	// SigningAlgorithm returns the signing algorithm specifications in the format of:
	// 1. RSASSA_PSS_2048_SHA256 (RSASSA algorithm with PSS padding 2048 bit key with a SHA256 digest)
	// 2. RSASSA_PSS_3072_SHA256 (RSASSA algorithm with PSS padding 3072 bit key with a SHA256 digest)
	// 3. RSASSA_PSS_4096_SHA256 (RSASSA algorithm with PSS padding 4096 bit key with a SHA256 digest)
	// 4. RSASSA_PKCS1V15_2048_SHA256 (RSASSA algorithm with PKCS #1 v1.5 padding 2048 bit key with a SHA256 digest)
	// 5. RSASSA_PKCS1V15_3072_SHA256 (RSASSA algorithm with PKCS #1 v1.5 padding 3072 bit key with a SHA256 digest)
	// 6. RSASSA_PKCS1V15_4096_SHA256 (RSASSA algorithm with PKCS #1 v1.5 padding 4096 bit key with a SHA256 digest)
	// 7. ECDSA_P256_SHA256 (ECDSA on the P-256 Curve with a SHA256 digest)
	SigningAlgorithm() (SigningAlgorithm, error)
}

// ValidSig checks if any errors occurred for the following methods:
// 1. Signature.Payload()
// 2. Signature.Base64Encoded()
// 3. Signature.PublicKey()
// 4. Signature.SigningAlgorithm()
func ValidSig(sig Signature) error {
	var err error
	if _, e := sig.Payload(); e != nil {
		err = multierr.Append(err, e)
	}
	if _, e := sig.Base64Encoded(); e != nil {
		err = multierr.Append(err, e)
	}
	if _, e := sig.PublicKey(); e != nil {
		err = multierr.Append(err, e)
	}
	if _, e := sig.SigningAlgorithm(); e != nil {
		err = multierr.Append(err, e)
	}
	return err
}
