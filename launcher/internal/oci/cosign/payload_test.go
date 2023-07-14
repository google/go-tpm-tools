package cosign

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestValidPayload(t *testing.T) {
	testCases := []struct {
		name     string
		payload  *Payload
		wantPass bool
	}{
		{
			name: "valid cosign payload format",
			payload: &Payload{
				Critical: Critical{
					Identity: Identity{
						DockerReference: "us-docker.pkg.dev/confidential-space-images-dev/cs-cosign-tests/base",
					},
					Image: Image{
						DockerManifestDigest: "sha256:9494e567c7c44e8b9f8808c1658a47c9b7979ef3cceef10f48754fc2706802ba",
					},
					Type: CosignCriticalType,
				},
			},
			wantPass: true,
		},
		{
			name: "invalid cosign payload format with invalid type",
			payload: &Payload{
				Critical: Critical{
					Identity: Identity{
						DockerReference: "us-docker.pkg.dev/confidential-space-images-dev/cs-cosign-tests/base",
					},
					Image: Image{
						DockerManifestDigest: "sha256:9494e567c7c44e8b9f8808c1658a47c9b7979ef3cceef10f48754fc2706802ba",
					},
					Type: "invalid type",
				},
			},
			wantPass: false,
		},
		{
			name: "invalid cosign payload format with invalid manifest digest",
			payload: &Payload{
				Critical: Critical{
					Identity: Identity{
						DockerReference: "us-docker.pkg.dev/confidential-space-images-dev/cs-cosign-tests/base",
					},
					Image: Image{
						DockerManifestDigest: "sha256:invalid manifest digest",
					},
					Type: CosignCriticalType,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.payload.Valid() == nil; got != tc.wantPass {
				t.Errorf("cosign payload Valid() failed for test case %v: got %v, but want %v", tc.name, got, tc.wantPass)
			}
		})
	}
}

func TestUnmarshalPayload(t *testing.T) {
	payloadBytes := []byte(`{"critical":{"identity":{"docker-reference":"us-docker.pkg.dev/confidential-space-images-dev/cs-cosign-tests/base"},"image":{"docker-manifest-digest":"sha256:9494e567c7c44e8b9f8808c1658a47c9b7979ef3cceef10f48754fc2706802ba"},"type":"cosign container image signature"},"optional":null}`)
	wantPayload := &Payload{
		Critical: Critical{
			Identity: Identity{
				DockerReference: "us-docker.pkg.dev/confidential-space-images-dev/cs-cosign-tests/base",
			},
			Image: Image{
				DockerManifestDigest: "sha256:9494e567c7c44e8b9f8808c1658a47c9b7979ef3cceef10f48754fc2706802ba",
			},
			Type: CosignCriticalType,
		},
	}
	gotPayload, err := UnmarshalPayload(payloadBytes)
	if err != nil {
		t.Errorf("UnmarshalPayload() failed: %v", err)
	}

	if !cmp.Equal(gotPayload, wantPayload) {
		t.Errorf("UnmarshalPayload() failed, got %v, but want %v", gotPayload, wantPayload)
	}
}
