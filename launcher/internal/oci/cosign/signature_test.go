package cosign

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestPayload(t *testing.T) {
	testCases := []struct {
		name        string
		blob        []byte
		wantDigest  digest.Digest
		wantPayload []byte
		wantPass    bool
	}{
		{
			name:        "cosign signature Payload() success",
			blob:        []byte(`{"critical":{"identity":{"docker-reference":"us-docker.pkg.dev/confidential-space-images-dev/cs-cosign-tests/base"},"image":{"docker-manifest-digest":"sha256:9494e567c7c44e8b9f8808c1658a47c9b7979ef3cceef10f48754fc2706802ba"},"type":"cosign container image signature"},"optional":null}`),
			wantDigest:  "sha256:d1e44a76902409836227b982beb920189949927c2011f196594bd34c5bb8f8b1",
			wantPayload: []byte(`{"critical":{"identity":{"docker-reference":"us-docker.pkg.dev/confidential-space-images-dev/cs-cosign-tests/base"},"image":{"docker-manifest-digest":"sha256:9494e567c7c44e8b9f8808c1658a47c9b7979ef3cceef10f48754fc2706802ba"},"type":"cosign container image signature"},"optional":null}`),
			wantPass:    true,
		},
		{
			name:        "cosign signature Payload() failed with unmatched digest",
			blob:        []byte(`{"critical":{"identity":{"docker-reference":"us-docker.pkg.dev/confidential-space-images-dev/cs-cosign-tests/base"},"image":{"docker-manifest-digest":"sha256:9494e567c7c44e8b9f8808c1658a47c9b7979ef3cceef10f48754fc2706802ba"},"type":"cosign container image signature"},"optional":null}`),
			wantDigest:  "sha256:unmatched digest",
			wantPayload: []byte{},
			wantPass:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sig := &Sig{
				Layer: v1.Descriptor{
					Digest: tc.wantDigest,
				},
				Blob: tc.blob,
			}
			gotPayload, err := sig.Payload()
			if err != nil && tc.wantPass {
				t.Errorf("Payload() failed for test case %v: %v", tc.name, err)
			}
			if !bytes.Equal(gotPayload, tc.wantPayload) {
				t.Errorf("Payload() failed for test case %v: got %v, but want %v", tc.name, gotPayload, tc.wantPayload)
			}
		})
	}
}

func TestBase64Encoded(t *testing.T) {
	testCases := []struct {
		name             string
		wantSignatureKey string
		wantSignature    string
		wantPass         bool
	}{
		{
			name:             "cosign signature Base64Encoded() success",
			wantSignatureKey: CosignSigKey,
			wantSignature:    randomBase64EncodedString(32),
			wantPass:         true,
		},
		{
			name:             "cosign signature Base64Encoded() failed with mismatched signature key",
			wantSignatureKey: "mismatched signature key",
			wantSignature:    "",
			wantPass:         false,
		},
		{
			name:             "cosign signature Base64Encoded() failed with invalid base64 encoded signature",
			wantSignatureKey: CosignSigKey,
			wantSignature:    "",
			wantPass:         false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sig := &Sig{
				Layer: v1.Descriptor{
					Annotations: map[string]string{
						tc.wantSignatureKey: tc.wantSignature,
					},
				},
			}
			gotSignature, err := sig.Base64Encoded()
			if err != nil && tc.wantPass {
				t.Errorf("Base64Encoded() failed for test case %v: %v", tc.name, err)
			}
			if gotSignature != tc.wantSignature {
				t.Errorf("Base64Encoded() failed for test case %v: got %v, but want %v", tc.name, gotSignature, tc.wantSignature)
			}
		})
	}
}

func TestWorkflow(t *testing.T) {
	wantSig := randomBase64EncodedString(32)
	blob := []byte(`{"critical":{"identity":{"docker-reference":"us-docker.pkg.dev/confidential-space-images-dev/cs-cosign-tests/base"},"image":{"docker-manifest-digest":"sha256:9494e567c7c44e8b9f8808c1658a47c9b7979ef3cceef10f48754fc2706802ba"},"type":"cosign container image signature"},"optional":null}`)

	sig := &Sig{
		Layer: v1.Descriptor{
			Digest: digest.FromBytes(blob),
			Annotations: map[string]string{
				CosignSigKey: wantSig,
			},
		},
		Blob: blob,
	}

	gotPayload, err := sig.Payload()
	if err != nil {
		t.Errorf("Payload() failed: %v", err)
	}
	if !bytes.Equal(gotPayload, blob) {
		t.Errorf("Payload() failed: got %v, but want %v", gotPayload, blob)
	}

	gotSig, err := sig.Base64Encoded()
	if err != nil {
		t.Errorf("Base64Encoded() failed: %v", err)
	}
	if gotSig != wantSig {
		t.Errorf("Base64Encoded() failed, got %s, but want %s", gotSig, wantSig)
	}
}

func TestString(t *testing.T) {
	testCases := []struct {
		name       string
		sourceRepo string
		b64Sig     string
		wantString string
	}{
		{
			name:       "successful signature details",
			sourceRepo: "gcr.io/hello_world",
			b64Sig:     "aGVsbG8gd29ybGQ=", // base64 encoded "hello world"
			wantString: `signature: "aGVsbG8gd29ybGQ=", sourceRepo: "gcr.io/hello_world"`,
		},
		{
			name:       "erronous signature details",
			sourceRepo: "gcr.io/hello_world",
			b64Sig:     "invalid",
			wantString: `signature error: invalid base64 encoded signature`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sig := &Sig{
				Layer: v1.Descriptor{
					Annotations: map[string]string{
						CosignSigKey: tc.b64Sig,
					},
				},
				SourceRepo: tc.sourceRepo,
			}
			gotString := sig.String()
			if !strings.Contains(gotString, tc.wantString) {
				t.Errorf("String() failed, got %s, but want %s", gotString, tc.wantString)
			}
		})
	}
}

func randomBase64EncodedString(n int) string {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return ""
	}
	return encoding.EncodeToString(b)
}
