package cosign

import (
	"encoding/base64"
	"fmt"

	"github.com/google/go-tpm-tools/launcher/internal/oci"
)

type fakeSig struct {
	data   string
	sigAlg oci.SigningAlgorithm
}

// NewFakeSignature constructs a new fake oci.Signature given data and signature algorithm.
func NewFakeSignature(data string, sigAlg oci.SigningAlgorithm) oci.Signature {
	return &fakeSig{data, sigAlg}
}

// Payload returns a fake payload.
func (f fakeSig) Payload() ([]byte, error) {
	return []byte(f.data), nil
}

// Base64Encoded returns a fake base64 encoded signature.
func (f fakeSig) Base64Encoded() (string, error) {
	return base64.StdEncoding.EncodeToString([]byte(f.data)), nil
}

// PublicKey returns a fake public key.
func (f fakeSig) PublicKey() ([]byte, error) {
	return []byte(f.data), nil
}

// SigningAlgorithm returns a fake signature algorithm.
func (f fakeSig) SigningAlgorithm() (oci.SigningAlgorithm, error) {
	switch f.sigAlg {
	case oci.ECDSAP256SHA256, oci.RSASSAPKCS1V152048SHA256, oci.RSASSAPSS2048SHA256:
		return f.sigAlg, nil
	default:
		return "", fmt.Errorf("unsupported signing algorithm: %v", f.sigAlg)
	}
}
