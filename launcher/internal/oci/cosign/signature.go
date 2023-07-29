// Package cosign contains functionalities to interact with signatures generated by cosign.
// https://github.com/sigstore/cosign/blob/main/specs/SIGNATURE_SPEC.md.
package cosign

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/google/go-tpm-tools/launcher/internal/oci"
	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

// Sig implements oci.Signature interface for cosign-generated signatures.
type Sig struct {
	// Layer represents a layer descriptor for OCI image manifest.
	// This contains the simple signing payload digest and Cosign signature,
	// collected from the OCI image manifest object found using https://github.com/sigstore/cosign/blob/main/specs/SIGNATURE_SPEC.md#tag-based-discovery.
	Layer v1.Descriptor
	// Blob represents the opaque data uploaded to OCI registry associated with the layer.
	// This contains the Simple Signing Payload as described in https://github.com/sigstore/cosign/blob/main/specs/SIGNATURE_SPEC.md#tag-based-discovery.
	Blob []byte
}

// CosignSigKey is the key of the cosign-generated signature embedded in OCI image manifest.
const CosignSigKey = "dev.cosignproject.cosign/signature"

var (
	// Verify that our Sig struct implements the expected public interface.
	_        oci.Signature = Sig{}
	encoding               = base64.StdEncoding
)

// Payload implements oci.Signature interface.
func (s Sig) Payload() ([]byte, error) {
	// The payload bytes are uploaded to an OCI registry as blob, and are referenced by digest.
	// This digiest is embedded into the OCI image manifest as a layer via a descriptor (see https://github.com/opencontainers/image-spec/blob/main/descriptor.md).
	// Here we compare the digest of the blob data with the layer digest to verify if this blob is associated with the layer.
	if digest.FromBytes(s.Blob) != s.Layer.Digest {
		return nil, errors.New("an unmatched payload digest is paired with a layer descriptor digest")
	}
	return s.Blob, nil
}

// Base64Encoded implements oci.Signature interface.
func (s Sig) Base64Encoded() (string, error) {
	sig, ok := s.Layer.Annotations[CosignSigKey]
	if !ok {
		return "", errors.New("cosign signature not found in the layer annotations")
	}
	if _, err := encoding.DecodeString(sig); err != nil {
		return "", fmt.Errorf("invalid base64 encoded signature: %w", err)
	}
	return sig, nil
}

// PublicKey implements oci.Signature interface.
// Since public key is attached to the `optional` field of payload, we don't actually implement this method.
// Instead we send payload directly to the Attestation service and let the service parse the payload.
func (s Sig) PublicKey() ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

// SigningAlgorithm implements oci.Signature interface.
// Since signing algorithm is attached to the `optional` field of payload, we don't actually implement this method.
// Instead we send payload directly to the Attestation service and let the service parse the payload.
func (s Sig) SigningAlgorithm() (oci.SigningAlgorithm, error) {
	return "", fmt.Errorf("not implemented")
}
