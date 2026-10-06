package signaturediscovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/content/local"
	"github.com/containerd/containerd/remotes"
	"github.com/containerd/platforms"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-tpm-tools/launcher/registryauth"
	"github.com/google/go-tpm-tools/verifier/oci/cosign"
	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestFormatSigTag(t *testing.T) {
	testCases := []struct {
		name       string
		imageDesc  v1.Descriptor
		wantSigTag string
	}{
		{
			name: "sha256 digest formatted with sig suffix",
			imageDesc: v1.Descriptor{
				Digest: "sha256:9ecc53c269509f63c69a266168e4a687c7eb8c0cfd753bd8bfcaa4f58a90876f",
			},
			wantSigTag: "sha256-9ecc53c269509f63c69a266168e4a687c7eb8c0cfd753bd8bfcaa4f58a90876f.sig",
		},
		{
			name: "alternate sha256 digest formatted with sig suffix",
			imageDesc: v1.Descriptor{
				Digest: "sha256:18740b995b4eac1b5706392a96ff8c4f30cefac18772058a71449692f1581f0f",
			},
			wantSigTag: "sha256-18740b995b4eac1b5706392a96ff8c4f30cefac18772058a71449692f1581f0f.sig",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatSigTag(tc.imageDesc); got != tc.wantSigTag {
				t.Errorf("formatSigTag(%v) = %q, want %q", tc.imageDesc.Digest, got, tc.wantSigTag)
			}
		})
	}
}

func TestFetchSignedImageManifest_Success(t *testing.T) {
	ctx := t.Context()
	testImage, wantManifest := createTestImage(ctx, t, [][]byte{[]byte("layer-content")})
	client := &Client{
		OriginalImageDesc: v1.Descriptor{
			Digest: "sha256:9ecc53c269509f63c69a266168e4a687c7eb8c0cfd753bd8bfcaa4f58a90876f",
		},
		imageFetcher: func(context.Context, string, ...containerd.RemoteOpt) (containerd.Image, error) {
			return testImage, nil
		},
	}

	gotManifest, err := client.FetchSignedImageManifest(ctx, "gcr.io/test/repo")
	if err != nil {
		t.Fatalf("FetchSignedImageManifest failed: %v", err)
	}
	if diff := cmp.Diff(wantManifest, gotManifest); diff != "" {
		t.Errorf("FetchSignedImageManifest mismatch (-want +got):\n%s", diff)
	}
}

func TestFetchSignedImageManifest_PullError(t *testing.T) {
	ctx := t.Context()
	wantErr := errors.New("pull failure")
	client := &Client{
		OriginalImageDesc: v1.Descriptor{
			Digest: "sha256:9ecc53c269509f63c69a266168e4a687c7eb8c0cfd753bd8bfcaa4f58a90876f",
		},
		imageFetcher: func(context.Context, string, ...containerd.RemoteOpt) (containerd.Image, error) {
			return nil, wantErr
		},
	}

	if _, err := client.FetchSignedImageManifest(ctx, "gcr.io/test/repo"); !errors.Is(err, wantErr) {
		t.Errorf("FetchSignedImageManifest got err %v, want %v", err, wantErr)
	}
}

func TestFetchSignedImageManifest_CorruptManifest(t *testing.T) {
	ctx := t.Context()
	cs, err := local.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("local.NewStore failed: %v", err)
	}
	corruptDesc := writeBlob(ctx, t, cs, []byte("not-json"), v1.MediaTypeImageManifest)
	testImage := &fakeImage{
		target: corruptDesc,
		store:  cs,
	}
	client := &Client{
		OriginalImageDesc: v1.Descriptor{
			Digest: "sha256:9ecc53c269509f63c69a266168e4a687c7eb8c0cfd753bd8bfcaa4f58a90876f",
		},
		imageFetcher: func(context.Context, string, ...containerd.RemoteOpt) (containerd.Image, error) {
			return testImage, nil
		},
	}

	if _, err := client.FetchSignedImageManifest(ctx, "gcr.io/test/repo"); err == nil {
		t.Error("FetchSignedImageManifest succeeded for corrupt manifest, want error")
	}
}

func TestFetchImageSignatures_Success(t *testing.T) {
	ctx := t.Context()
	layerPayload := []byte("cosign-signing-payload")
	testImage, _ := createTestImage(ctx, t, [][]byte{layerPayload})
	client := &Client{
		OriginalImageDesc: v1.Descriptor{
			Digest: "sha256:9ecc53c269509f63c69a266168e4a687c7eb8c0cfd753bd8bfcaa4f58a90876f",
		},
		imageFetcher: func(context.Context, string, ...containerd.RemoteOpt) (containerd.Image, error) {
			return testImage, nil
		},
	}

	targetRepo := "gcr.io/test/repo"
	signatures, err := client.FetchImageSignatures(ctx, targetRepo)
	if err != nil {
		t.Fatalf("FetchImageSignatures failed: %v", err)
	}
	if len(signatures) != 1 {
		t.Fatalf("FetchImageSignatures returned %d signatures, want 1", len(signatures))
	}

	sig := signatures[0]
	gotPayload, err := sig.Payload()
	if err != nil {
		t.Fatalf("sig.Payload() failed: %v", err)
	}
	if diff := cmp.Diff(layerPayload, gotPayload); diff != "" {
		t.Errorf("sig.Payload() mismatch (-want +got):\n%s", diff)
	}

	gotBase64, err := sig.Base64Encoded()
	if err != nil {
		t.Fatalf("sig.Base64Encoded() failed: %v", err)
	}
	if gotBase64 != fakeBase64Sig {
		t.Errorf("sig.Base64Encoded() = %q, want %q", gotBase64, fakeBase64Sig)
	}
}

func TestFetchImageSignatures_PullError(t *testing.T) {
	ctx := t.Context()
	wantErr := errors.New("pull failure")
	client := &Client{
		OriginalImageDesc: v1.Descriptor{
			Digest: "sha256:9ecc53c269509f63c69a266168e4a687c7eb8c0cfd753bd8bfcaa4f58a90876f",
		},
		imageFetcher: func(context.Context, string, ...containerd.RemoteOpt) (containerd.Image, error) {
			return nil, wantErr
		},
	}

	if _, err := client.FetchImageSignatures(ctx, "gcr.io/test/repo"); !errors.Is(err, wantErr) {
		t.Errorf("FetchImageSignatures got err %v, want %v", err, wantErr)
	}
}

func TestFetchImageSignatures_ManifestReadError(t *testing.T) {
	ctx := t.Context()
	cs, err := local.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("local.NewStore failed: %v", err)
	}
	corruptDesc := writeBlob(ctx, t, cs, []byte("invalid-manifest"), v1.MediaTypeImageManifest)
	testImage := &fakeImage{
		target: corruptDesc,
		store:  cs,
	}
	client := &Client{
		OriginalImageDesc: v1.Descriptor{
			Digest: "sha256:9ecc53c269509f63c69a266168e4a687c7eb8c0cfd753bd8bfcaa4f58a90876f",
		},
		imageFetcher: func(context.Context, string, ...containerd.RemoteOpt) (containerd.Image, error) {
			return testImage, nil
		},
	}

	if _, err := client.FetchImageSignatures(ctx, "gcr.io/test/repo"); err == nil {
		t.Error("FetchImageSignatures succeeded for corrupt manifest, want error")
	}
}

func TestFetchImageSignatures_LayerBlobMissing(t *testing.T) {
	ctx := t.Context()
	cs, err := local.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("local.NewStore failed: %v", err)
	}

	missingLayerDesc := v1.Descriptor{
		MediaType: v1.MediaTypeImageLayer,
		Digest:    digest.FromString("missing-layer"),
		Size:      100,
	}
	configDesc := writeBlob(ctx, t, cs, []byte("{}"), v1.MediaTypeImageConfig)
	manifest := v1.Manifest{
		MediaType: v1.MediaTypeImageManifest,
		Config:    configDesc,
		Layers: []v1.Descriptor{
			missingLayerDesc,
		},
	}
	manifest.SchemaVersion = 2
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	manifestDesc := writeBlob(ctx, t, cs, manifestBytes, v1.MediaTypeImageManifest)

	testImage := &fakeImage{
		target: manifestDesc,
		store:  cs,
	}
	client := &Client{
		OriginalImageDesc: v1.Descriptor{
			Digest: "sha256:9ecc53c269509f63c69a266168e4a687c7eb8c0cfd753bd8bfcaa4f58a90876f",
		},
		imageFetcher: func(context.Context, string, ...containerd.RemoteOpt) (containerd.Image, error) {
			return testImage, nil
		},
	}

	if _, err := client.FetchImageSignatures(ctx, "gcr.io/test/repo"); err == nil {
		t.Error("FetchImageSignatures succeeded when layer blob is missing, want error")
	}
}

func TestPullSignatureImage_WithResolver_Succeeds(t *testing.T) {
	ctx := t.Context()
	var passedOpts []containerd.RemoteOpt
	client := &Client{
		OriginalImageDesc: v1.Descriptor{
			Digest: "sha256:905a0f3b3d6d0fb37bfa448b9e78f833b73f0b19fc97fed821a09cf49e255df1",
		},
		refreshResolver: func(context.Context) (remotes.Resolver, error) {
			return registryauth.Resolver("valid access", http.DefaultClient), nil
		},
		imageFetcher: func(_ context.Context, _ string, opts ...containerd.RemoteOpt) (containerd.Image, error) {
			passedOpts = opts
			return &fakeImage{}, nil
		},
	}

	img, err := client.pullSignatureImage(ctx, "fake image repo")
	if err != nil {
		t.Fatalf("pullSignatureImage failed: %v", err)
	}
	if img == nil {
		t.Error("pullSignatureImage returned nil image, want non-nil")
	}
	if len(passedOpts) == 0 {
		t.Error("pullSignatureImage did not pass remote options to image fetcher")
	}
}

func TestPullSignatureImage_NilResolver_Succeeds(t *testing.T) {
	ctx := t.Context()
	var passedOpts []containerd.RemoteOpt
	client := &Client{
		OriginalImageDesc: v1.Descriptor{
			Digest: "sha256:905a0f3b3d6d0fb37bfa448b9e78f833b73f0b19fc97fed821a09cf49e255df1",
		},
		refreshResolver: nil,
		imageFetcher: func(_ context.Context, _ string, opts ...containerd.RemoteOpt) (containerd.Image, error) {
			passedOpts = opts
			return &fakeImage{}, nil
		},
	}

	img, err := client.pullSignatureImage(ctx, "fake image repo")
	if err != nil {
		t.Fatalf("pullSignatureImage failed: %v", err)
	}
	if img == nil {
		t.Error("pullSignatureImage returned nil image, want non-nil")
	}
	if len(passedOpts) != 0 {
		t.Errorf("pullSignatureImage passed %d opts for nil resolver, want 0", len(passedOpts))
	}
}

func TestPullSignatureImage_ResolverError_Fails(t *testing.T) {
	ctx := t.Context()
	wantErr := errors.New("invalid resolver")
	client := &Client{
		OriginalImageDesc: v1.Descriptor{
			Digest: "sha256:905a0f3b3d6d0fb37bfa448b9e78f833b73f0b19fc97fed821a09cf49e255df1",
		},
		refreshResolver: func(context.Context) (remotes.Resolver, error) {
			return nil, wantErr
		},
		imageFetcher: func(context.Context, string, ...containerd.RemoteOpt) (containerd.Image, error) {
			return &fakeImage{}, nil
		},
	}

	_, err := client.pullSignatureImage(ctx, "fake image repo")
	if err == nil {
		t.Fatal("pullSignatureImage succeeded with failing resolver, want error")
	}
	wantErrSubstr := "failed to refresh remote resolver before pulling container image: invalid resolver"
	if !strings.Contains(err.Error(), wantErrSubstr) {
		t.Errorf("pullSignatureImage error = %q, want substring %q", err.Error(), wantErrSubstr)
	}
}

const fakeBase64Sig = "MEUCIQDgoiwMiVl1SAI1iePhH6Oeqztms3IwNtN+w0P92HTqQgIgKjJNcHEy0Ep4g4MH1Vd0gAHvbwH9ahD+jlnMP/rXSGE="

type fakeImage struct {
	containerd.Image
	target v1.Descriptor
	store  content.Store
}

func (f *fakeImage) Target() v1.Descriptor {
	return f.target
}

func (f *fakeImage) ContentStore() content.Store {
	return f.store
}

func (f *fakeImage) Platform() platforms.MatchComparer {
	return platforms.All
}

func writeBlob(ctx context.Context, t *testing.T, cs content.Store, data []byte, mediaType string) v1.Descriptor {
	t.Helper()
	d := digest.FromBytes(data)
	desc := v1.Descriptor{
		MediaType: mediaType,
		Digest:    d,
		Size:      int64(len(data)),
	}
	if err := content.WriteBlob(ctx, cs, string(d), bytes.NewReader(data), desc); err != nil {
		t.Fatalf("failed to write blob: %v", err)
	}
	return desc
}

func createTestImage(ctx context.Context, t *testing.T, layers [][]byte) (containerd.Image, v1.Manifest) {
	t.Helper()
	cs, err := local.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create local store: %v", err)
	}

	var layerDescs []v1.Descriptor
	for _, layerData := range layers {
		desc := writeBlob(ctx, t, cs, layerData, v1.MediaTypeImageLayer)
		desc.Annotations = map[string]string{
			cosign.CosignSigKey: fakeBase64Sig,
		}
		layerDescs = append(layerDescs, desc)
	}

	configDesc := writeBlob(ctx, t, cs, []byte("{}"), v1.MediaTypeImageConfig)

	manifest := v1.Manifest{
		MediaType: v1.MediaTypeImageManifest,
		Config:    configDesc,
		Layers:    layerDescs,
	}
	manifest.SchemaVersion = 2

	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("failed to marshal manifest: %v", err)
	}

	manifestDesc := writeBlob(ctx, t, cs, manifestBytes, v1.MediaTypeImageManifest)

	return &fakeImage{
		target: manifestDesc,
		store:  cs,
	}, manifest
}
