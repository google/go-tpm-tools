// Package oci contains functionalities to interact with OCI image signatures.
// https://github.com/opencontainers/image-spec/tree/main#readme.
package oci

import "go.uber.org/multierr"

// Signature represents a single OCI image signature.
type Signature interface {
	// Payload returns the blob data associated with a signature uploaded to an OCI registry.
	Payload() ([]byte, error)

	// Base64Encoded returns the base64-encoded signature of the signed payload.
	Base64Encoded() (string, error)

	// PubBase64Encoded returns the base64-encoded public key that will verify the signature.
	PubBase64Encoded() (string, error)

	// SigningAlgorithm returns the signing algorithm specifications in the format of:
	// 1. RSASSA_PSS_SHA256 (RSASSA algorithm with PSS padding with a SHA256 digest)
	// 2. RSASSA_PKCS1V15_SHA256 (RSASSA algorithm with PKCS #1 v1.5 padding with a SHA256 digest)
	// 3. ECDSA_P256_SHA256 (ECDSA on the P-256 Curve with a SHA256 digest)
	SigningAlgorithm() (string, error)
}

// ValidSig performs validity checks on the given OCI signature.
func ValidSig(sig Signature) error {
	var err error
	if _, e := sig.Payload(); e != nil {
		err = multierr.Append(err, e)
	}
	if _, e := sig.Base64Encoded(); e != nil {
		err = multierr.Append(err, e)
	}
	if _, e := sig.PubBase64Encoded(); e != nil {
		err = multierr.Append(err, e)
	}
	if _, e := sig.SigningAlgorithm(); e != nil {
		err = multierr.Append(err, e)
	}
	return err
}
