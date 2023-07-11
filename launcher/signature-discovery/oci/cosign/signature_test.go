package cosign

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-tpm-tools/launcher/signature-discovery/oci"
	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

const pubKey = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCNEi/TiRoeS29nnSCTGX61+Z/3
6mKZmEoC81cFAYSV5f+K6oR7dwqz14wCJSNleCLLGHYfGSeWIimcfzwK6Ar93RJm
+k1wjGBmAZawd1AkIWRAXW7TzRPbO30xSpcnQ1M1bZTyjXioEDkCuB0DLpHj2gc7
q/hY7zZO8rnRN1xzTwIDAQAB
-----END PUBLIC KEY-----`

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

func TestPublicKey(t *testing.T) {
	testCases := []struct {
		name        string
		wantPayload []byte
		wantPubKey  []byte
		wantPass    bool
	}{
		{
			name:        "cosign signature PublicKey() success",
			wantPayload: []byte(`{"critical":{"identity":{"docker-reference":"us-docker.pkg.dev/confidential-space-images-dev/cs-cosign-tests/base"},"image":{"docker-manifest-digest":"sha256:9494e567c7c44e8b9f8808c1658a47c9b7979ef3cceef10f48754fc2706802ba"},"type":"cosign container image signature"},"optional":{"dev.cosignproject.cosign/pub": "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCNEi/TiRoeS29nnSCTGX61+Z/3\n6mKZmEoC81cFAYSV5f+K6oR7dwqz14wCJSNleCLLGHYfGSeWIimcfzwK6Ar93RJm\n+k1wjGBmAZawd1AkIWRAXW7TzRPbO30xSpcnQ1M1bZTyjXioEDkCuB0DLpHj2gc7\nq/hY7zZO8rnRN1xzTwIDAQAB\n-----END PUBLIC KEY-----"}}`),
			wantPubKey:  []byte(pubKey), // PEM-encoded byte slide of public key
			wantPass:    true,
		},
		{
			name:        "cosign signature PublicKey() failed with invalid payload format",
			wantPayload: []byte(`{"invalid payload format": "invalid"}`),
			wantPubKey:  nil,
			wantPass:    false,
		},
		{
			name:        "cosign signature PublicKey() failed with no public key found",
			wantPayload: []byte(`{"critical":{"identity":{"docker-reference":"us-docker.pkg.dev/confidential-space-images-dev/cs-cosign-tests/base"},"image":{"docker-manifest-digest":"sha256:9494e567c7c44e8b9f8808c1658a47c9b7979ef3cceef10f48754fc2706802ba"},"type":"cosign container image signature"},"optional":null}`),
			wantPubKey:  nil,
			wantPass:    false,
		},
		{
			name:        "cosign signature PublicKey() failed with invalid PEM encoded public key",
			wantPayload: []byte(`{"critical":{"identity":{"docker-reference":"us-docker.pkg.dev/confidential-space-images-dev/cs-cosign-tests/base"},"image":{"docker-manifest-digest":"sha256:9494e567c7c44e8b9f8808c1658a47c9b7979ef3cceef10f48754fc2706802ba"},"type":"cosign container image signature"},"optional":{"dev.cosignproject.cosign/pub": "invalid pub key"}}`),
			wantPubKey:  nil,
			wantPass:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sig := &Sig{
				Layer: v1.Descriptor{
					Digest: digest.FromBytes(tc.wantPayload),
				},
				Blob: tc.wantPayload,
			}
			gotPubKey, err := sig.PublicKey()
			if err != nil && tc.wantPass {
				t.Errorf("PublicKey() failed for test case %v: %v", tc.name, err)
			}
			if !bytes.Equal(gotPubKey, tc.wantPubKey) {
				t.Errorf("PublicKey() failed for test case %v: got %v, but want %v", tc.name, gotPubKey, tc.wantPubKey)
			}
		})
	}
}

func TestSigningAlgorithm(t *testing.T) {
	testCases := []struct {
		name        string
		wantPayload []byte
		wantSigAlg  oci.SigningAlgorithm
		wantPass    bool
	}{
		{
			name:        "cosign signature SigningAlgorithm() success",
			wantPayload: []byte(`{"critical":{"identity":{"docker-reference":"us-docker.pkg.dev/confidential-space-images-dev/cs-cosign-tests/base"},"image":{"docker-manifest-digest":"sha256:9494e567c7c44e8b9f8808c1658a47c9b7979ef3cceef10f48754fc2706802ba"},"type":"cosign container image signature"},"optional":{"dev.cosignproject.cosign/signingalgo": "RSASSA_PSS_SHA256"}}`),
			wantSigAlg:  oci.RsassaPssSha256,
			wantPass:    true,
		},
		{
			name:        "cosign signature SigningAlgorithm() failed with no signing algorithm found",
			wantPayload: []byte(`{"critical":{"identity":{"docker-reference":"us-docker.pkg.dev/confidential-space-images-dev/cs-cosign-tests/base"},"image":{"docker-manifest-digest":"sha256:9494e567c7c44e8b9f8808c1658a47c9b7979ef3cceef10f48754fc2706802ba"},"type":"cosign container image signature"},"optional":null}`),
			wantSigAlg:  "",
			wantPass:    false,
		},
		{
			name:        "cosign signature SigningAlgorithm() failed with unsupported signing algorithm",
			wantPayload: []byte(`{"critical":{"identity":{"docker-reference":"us-docker.pkg.dev/confidential-space-images-dev/cs-cosign-tests/base"},"image":{"docker-manifest-digest":"sha256:9494e567c7c44e8b9f8808c1658a47c9b7979ef3cceef10f48754fc2706802ba"},"type":"cosign container image signature"},"optional":{"dev.cosignproject.cosign/signingalgo": "unsupported signing algorithm"}}`),
			wantSigAlg:  "",
			wantPass:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sig := &Sig{
				Layer: v1.Descriptor{
					Digest: digest.FromBytes(tc.wantPayload),
				},
				Blob: tc.wantPayload,
			}
			gotSigAlg, err := sig.SigningAlgorithm()
			if err != nil && tc.wantPass {
				t.Errorf("SigningAlgorithm() failed for test case %v: %v", tc.name, err)
			}
			if gotSigAlg != tc.wantSigAlg {
				t.Errorf("SigningAlgorithm() failed for test case %v: got %v, but want %v", tc.name, gotSigAlg, tc.wantSigAlg)
			}
		})
	}
}

func TestWorkflow(t *testing.T) {
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
		Optional: map[string]interface{}{
			CosignPubKey:      pubKey,
			CosignSigningAlgo: string(oci.RsassaPkcs1v15Sha256),
		},
	}
	wantSig := randomBase64EncodedString(32)

	blob, err := json.Marshal(wantPayload)
	if err != nil {
		t.Fatalf("unable to marshal payload: %v", err)
	}

	sig := &Sig{
		Layer: v1.Descriptor{
			Digest: digest.FromBytes(blob),
			Annotations: map[string]string{
				CosignSigKey: wantSig,
			},
		},
		Blob: blob,
	}

	payloadBytes, err := sig.Payload()
	if err != nil {
		t.Errorf("Payload() failed: %v", err)
	}
	gotPayload, _ := UnmarshalPayload(payloadBytes)
	if !cmp.Equal(gotPayload, wantPayload) {
		t.Errorf("Payload() failed, got %v, but want %v", gotPayload, wantPayload)
	}

	gotSig, err := sig.Base64Encoded()
	if err != nil {
		t.Errorf("Base64Encoded() failed: %v", err)
	}
	if gotSig != wantSig {
		t.Errorf("Base64Encoded() failed, got %s, but want %s", gotSig, wantSig)
	}

	wantPub := wantPayload.Optional[CosignPubKey].(string)
	gotPub, err := sig.PublicKey()
	if err != nil {
		t.Errorf("PublicKey() failed: %v", err)
	}
	if !bytes.Equal(gotPub, []byte(wantPub)) {
		t.Errorf("PublicKey() failed, got %v, but want %v", gotPub, []byte(wantPub))
	}

	wantSigAlg := wantPayload.Optional[CosignSigningAlgo].(string)
	gotSigAlg, err := sig.SigningAlgorithm()
	if err != nil {
		t.Errorf("SigningAlgorithm() failed: %v", err)
	}
	if gotSigAlg != oci.SigningAlgorithm(wantSigAlg) {
		t.Errorf("SigningAlgorithm() failed, got %v, but want %v", gotSigAlg, wantSigAlg)
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
