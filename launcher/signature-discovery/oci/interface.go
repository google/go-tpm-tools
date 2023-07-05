// Package oci contains functionalities to interact with OCI image signatures.
// https://github.com/opencontainers/image-spec/tree/main#readme.
package oci

import "context"

// Signature represents a single OCI image signature.
type Signature interface {
	// Payload returns the blob data associated with a signature uploaded to an OCI registry.
	Payload(ctx context.Context) ([]byte, error)

	// Base64Encoded returns the base64-encoded signature of the signed payload.
	Base64Encoded(ctx context.Context) (string, error)

	// PubBase64Encoded returns the base64-encoded public key that will verify the signature.
	PubBase64Encoded(ctx context.Context) (string, error)

	// SigningAlgorithm returns the signing algorithm specifications in the format of:
	// 1. RSASSA_PSS_SHA256 (RSASSA algorithm with PSS padding with a SHA256 digest)
	// 2. RSASSA_PKCS1_V1_5_SHA256 (RSASSA algorithm with PKCS #1 v1.5 padding with a SHA256 digest)
	// 3. ECDSA_P256_SHA256 (ECDSA on the P-256 Curve with a SHA256 digest)
	SigningAlgorithm(ctx context.Context) (string, error)
}
