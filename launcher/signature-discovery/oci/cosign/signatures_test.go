package cosign

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"os"
	"testing"

	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/content/local"
	"github.com/google/go-cmp/cmp"

	"github.com/containerd/containerd/namespaces"
	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestPayload(t *testing.T) {
	ctx := namespaces.WithNamespace(context.Background(), "test")

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
			cs := createLocalContentStore(t)
			writeBlob(ctx, t, cs, tc.blob)
			sig := &Sig{
				Layer: v1.Descriptor{
					Digest: tc.wantDigest,
				},
				Blob: cs,
			}
			gotPayload, err := sig.Payload(ctx)
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
	ctx := namespaces.WithNamespace(context.Background(), "test")

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
			gotSignature, err := sig.Base64Encoded(ctx)
			if err != nil && tc.wantPass {
				t.Errorf("Base64Encoded() failed for test case %v: %v", tc.name, err)
			}
			if gotSignature != tc.wantSignature {
				t.Errorf("Base64Encoded() failed for test case %v: got %v, but want %v", tc.name, gotSignature, tc.wantSignature)
			}
		})
	}
}

func TestPubBase64Encoded(t *testing.T) {
	ctx := namespaces.WithNamespace(context.Background(), "test")

	testCases := []struct {
		name        string
		wantPayload []byte
		wantPubKey  string
		wantPass    bool
	}{
		{
			name:        "cosign signature PubBase64Encoded() success",
			wantPayload: []byte(`{"critical":{"identity":{"docker-reference":"us-docker.pkg.dev/confidential-space-images-dev/cs-cosign-tests/base"},"image":{"docker-manifest-digest":"sha256:9494e567c7c44e8b9f8808c1658a47c9b7979ef3cceef10f48754fc2706802ba"},"type":"cosign container image signature"},"optional":{"dev.cosignproject.cosign/pub": "aGVsbG8gd29ybGQ="}}`),
			wantPubKey:  "aGVsbG8gd29ybGQ=", // base64 encoded "hello world"
			wantPass:    true,
		},
		{
			name:        "cosign signature PubBase64Encoded() failed with invalid payload format",
			wantPayload: []byte(`{"invalid payload format": "invalid"}`),
			wantPubKey:  "",
			wantPass:    false,
		},
		{
			name:        "cosign signature PubBase64Encoded() failed with no public key found",
			wantPayload: []byte(`{"critical":{"identity":{"docker-reference":"us-docker.pkg.dev/confidential-space-images-dev/cs-cosign-tests/base"},"image":{"docker-manifest-digest":"sha256:9494e567c7c44e8b9f8808c1658a47c9b7979ef3cceef10f48754fc2706802ba"},"type":"cosign container image signature"},"optional":null}`),
			wantPubKey:  "",
			wantPass:    false,
		},
		{
			name:        "cosign signature PubBase64Encoded() failed with invalid base64 encoded public key",
			wantPayload: []byte(`{"critical":{"identity":{"docker-reference":"us-docker.pkg.dev/confidential-space-images-dev/cs-cosign-tests/base"},"image":{"docker-manifest-digest":"sha256:9494e567c7c44e8b9f8808c1658a47c9b7979ef3cceef10f48754fc2706802ba"},"type":"cosign container image signature"},"optional":{"dev.cosignproject.cosign/pub": "invalid pub key"}}`),
			wantPubKey:  "",
			wantPass:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cs := createLocalContentStore(t)
			writeBlob(ctx, t, cs, tc.wantPayload)
			sig := &Sig{
				Layer: v1.Descriptor{
					Digest: digest.FromBytes(tc.wantPayload),
				},
				Blob: cs,
			}
			gotPubKey, err := sig.PubBase64Encoded(ctx)
			if err != nil && tc.wantPass {
				t.Errorf("PubBase64Encoded() failed for test case %v: %v", tc.name, err)
			}
			if gotPubKey != tc.wantPubKey {
				t.Errorf("PubBase64Encoded() failed for test case %v: got %v, but want %v", tc.name, gotPubKey, tc.wantPubKey)
			}
		})
	}
}

func TestSigningAlgorithm(t *testing.T) {
	ctx := namespaces.WithNamespace(context.Background(), "test")

	testCases := []struct {
		name        string
		wantPayload []byte
		wantSigAlg  string
		wantPass    bool
	}{
		{
			name:        "cosign signature SigningAlgorithm() success",
			wantPayload: []byte(`{"critical":{"identity":{"docker-reference":"us-docker.pkg.dev/confidential-space-images-dev/cs-cosign-tests/base"},"image":{"docker-manifest-digest":"sha256:9494e567c7c44e8b9f8808c1658a47c9b7979ef3cceef10f48754fc2706802ba"},"type":"cosign container image signature"},"optional":{"dev.cosignproject.cosign/signingalgo": "RSASSA_PSS_SHA256"}}`),
			wantSigAlg:  RsassaPssSha256,
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
			cs := createLocalContentStore(t)
			writeBlob(ctx, t, cs, tc.wantPayload)
			sig := &Sig{
				Layer: v1.Descriptor{
					Digest: digest.FromBytes(tc.wantPayload),
				},
				Blob: cs,
			}
			gotSigAlg, err := sig.SigningAlgorithm(ctx)
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
	ctx := namespaces.WithNamespace(context.Background(), "test")

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
			CosignPubKey:      randomBase64EncodedString(32),
			CosignSigningAlgo: RsassaPkcs1v5Sha256,
		},
	}
	wantSig := randomBase64EncodedString(32)

	cs := createLocalContentStore(t)
	blob, err := json.Marshal(wantPayload)
	if err != nil {
		t.Fatalf("unable to marshal payload: %v", err)
	}
	writeBlob(ctx, t, cs, blob)

	sig := &Sig{
		Layer: v1.Descriptor{
			Digest: digest.FromBytes(blob),
			Annotations: map[string]string{
				CosignSigKey: wantSig,
			},
		},
		Blob: cs,
	}

	payloadBytes, err := sig.Payload(ctx)
	if err != nil {
		t.Errorf("Payload() failed: %v", err)
	}
	gotPayload, _ := UnmarshalPayload(payloadBytes)
	if !cmp.Equal(gotPayload, wantPayload) {
		t.Errorf("Payload() failed, got %v, but want %v", gotPayload, wantPayload)
	}

	gotSig, err := sig.Base64Encoded(ctx)
	if err != nil {
		t.Errorf("Base64Encoded() failed: %v", err)
	}
	if gotSig != wantSig {
		t.Errorf("Base64Encoded() failed, got %s, but want %s", gotSig, wantSig)
	}

	wantPub := wantPayload.Optional[CosignPubKey]
	gotPub, err := sig.PubBase64Encoded(ctx)
	if err != nil {
		t.Errorf("PubBase64Encoded() failed: %v", err)
	}
	if gotPub != wantPub {
		t.Errorf("PubBase64Encoded() failed, got %v, but want %v", gotPub, wantPub)
	}

	wantSigAlg := wantPayload.Optional[CosignSigningAlgo]
	gotSigAlg, err := sig.SigningAlgorithm(ctx)
	if err != nil {
		t.Errorf("SigningAlgorithm() failed: %v", err)
	}
	if gotSigAlg != wantSigAlg {
		t.Errorf("SigningAlgorithm() failed, got %v, but want %v", gotSigAlg, wantSigAlg)
	}
}

func createLocalContentStore(t *testing.T) content.Store {
	tmpdir := t.TempDir()
	t.Cleanup(func() { os.RemoveAll(tmpdir) })
	store, err := local.NewStore(tmpdir)
	if err != nil {
		t.Fatalf("unable to create a local content store: %v", err)
	}
	return store
}

func writeBlob(ctx context.Context, t *testing.T, cs content.Store, blob []byte) {
	total := int64(len(blob))
	writer, err := cs.Writer(ctx, content.WithRef("ref"), content.WithDescriptor(v1.Descriptor{Size: total}))
	if err != nil {
		t.Fatalf("unable to create a content store writer: %v", err)
	}
	t.Cleanup(func() { writer.Close() })
	_, err = writer.Write(blob)
	if err != nil {
		t.Fatalf("unable to write payload blob: %v", err)
	}
	dgst := digest.FromBytes(blob)
	err = writer.Commit(ctx, total, dgst)
	if err != nil {
		t.Fatalf("unable to commit a blob: %v", err)
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
