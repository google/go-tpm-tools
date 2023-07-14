package cosign

import (
	"encoding/json"
	"fmt"

	digest "github.com/opencontainers/go-digest"
)

// CosignCriticalType is the value of `critical.type` in a simple signing format payload specified in
// https://github.com/sigstore/cosign/blob/main/specs/SIGNATURE_SPEC.md#simple-signing
const CosignCriticalType = "cosign container image signature"

// Payload follows the simple signing format specified in
// https://github.com/sigstore/cosign/blob/main/specs/SIGNATURE_SPEC.md#simple-signing
type Payload struct {
	Critical Critical               `json:"critical"`
	Optional map[string]interface{} `json:"optional"`
}

// Critical contains data critical to correctly evaluating the validity of a signature.
type Critical struct {
	Identity Identity `json:"identity"`
	Image    Image    `json:"image"`
	Type     string   `json:"type"`
}

// Identity identifies the claimed identity of the image.
type Identity struct {
	DockerReference string `json:"docker-reference"`
}

// Image identifies the container image this signature applies to.
type Image struct {
	DockerManifestDigest string `json:"docker-manifest-digest"`
}

// Valid returns error if the payload does not conform to simple signing format.
// https://github.com/sigstore/cosign/blob/main/specs/SIGNATURE_SPEC.md#simple-signing
func (p *Payload) Valid() error {
	if p.Critical.Type != CosignCriticalType {
		return fmt.Errorf("unknown critical type for Cosign signature payload: %s", p.Critical.Type)
	}
	if _, err := digest.Parse(p.Critical.Image.DockerManifestDigest); err != nil {
		return fmt.Errorf("cannot parse image digest: %w", err)
	}
	return nil
}

// UnmarshalPayload unmarshals a byte slice to a payload and performs checks on the payload.
func UnmarshalPayload(data []byte) (*Payload, error) {
	var payload Payload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}
	if err := payload.Valid(); err != nil {
		return nil, err
	}
	return &payload, nil
}
