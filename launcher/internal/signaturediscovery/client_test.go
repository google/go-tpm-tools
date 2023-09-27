package signaturediscovery

import (
	"context"
	"testing"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/defaults"
	"github.com/containerd/containerd/namespaces"
	"github.com/google/go-cmp/cmp"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestFormatSigTag(t *testing.T) {
	testCases := []struct {
		name       string
		imageDesc  v1.Descriptor
		wantSigTag string
		wantPass   bool
	}{
		{
			name:       "formatSigTag success",
			imageDesc:  v1.Descriptor{Digest: "sha256:9ecc53c269509f63c69a266168e4a687c7eb8c0cfd753bd8bfcaa4f58a90876f"},
			wantSigTag: "sha256-9ecc53c269509f63c69a266168e4a687c7eb8c0cfd753bd8bfcaa4f58a90876f.sig",
			wantPass:   true,
		},
		{
			name:       "formatSigTag failed with wrong image digest",
			imageDesc:  v1.Descriptor{Digest: "sha256:9ecc53c269509f63c69a266168e4a687c7eb8c0cfd753bd8bfcaa4f58a90876f"},
			wantSigTag: "sha256-18740b995b4eac1b5706392a96ff8c4f30cefac18772058a71449692f1581f0f.sig",
			wantPass:   false,
		},
		{
			name:       "formatSigTag failed with wrong tag format",
			imageDesc:  v1.Descriptor{Digest: "sha256:9ecc53c269509f63c69a266168e4a687c7eb8c0cfd753bd8bfcaa4f58a90876f"},
			wantSigTag: "sha256@9ecc53c269509f63c69a266168e4a687c7eb8c0cfd753bd8bfcaa4f58a90876f.sig",
			wantPass:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatSigTag(tc.imageDesc) == tc.wantSigTag; got != tc.wantPass {
				t.Errorf("formatSigTag() failed for test case %v: got %v, wantPass %v", tc.name, got, tc.wantPass)
			}
		})
	}
}

func TestFetchSignedImageManifestDockerPublic(t *testing.T) {
	ctx := namespaces.WithNamespace(context.Background(), "test")

	targetRepository := "gcr.io/distroless/static"
	originalImageDesc := v1.Descriptor{Digest: "sha256:9ecc53c269509f63c69a266168e4a687c7eb8c0cfd753bd8bfcaa4f58a90876f"}
	client := createTestClient(t, originalImageDesc)
	// testing image manifest fetching using a public docker repo url
	if _, err := client.FetchSignedImageManifest(ctx, targetRepository); err != nil {
		t.Errorf("failed to fetch signed image manifest from targetRepository [%s]: %v", targetRepository, err)
	}
}

func TestFetchImageSignaturesDockerPublic(t *testing.T) {
	ctx := namespaces.WithNamespace(context.Background(), "test")
	originalImageDesc := v1.Descriptor{Digest: "sha256:905a0f3b3d6d0fb37bfa448b9e78f833b73f0b19fc97fed821a09cf49e255df1"}
	targetRepository := "us-docker.pkg.dev/vegas-codelab-5/cosign-test/base"

	client := createTestClient(t, originalImageDesc)
	signatures, err := client.FetchImageSignatures(ctx, targetRepository)
	if err != nil {
		t.Errorf("failed to fetch image signatures from targetRepository [%s]: %v", targetRepository, err)
	}
	if len(signatures) == 0 {
		t.Errorf("no image signatures found for the original image %v", originalImageDesc)
	}
	var gotBase64Sigs []string
	for _, sig := range signatures {
		if _, err := sig.Payload(); err != nil {
			t.Errorf("Payload() failed: %v", err)
		}
		base64Sig, err := sig.Base64Encoded()
		if err != nil {
			t.Errorf("Base64Encoded() failed: %v", err)
		}
		gotBase64Sigs = append(gotBase64Sigs, base64Sig)
	}

	// Check signatures from the OCI image manifest at https://pantheon.corp.google.com/artifacts/docker/vegas-codelab-5/us/cosign-test/base/sha256:1febaa6ac3a5c095435d5276755fb8efcb7f029fefe85cd9bf3ec7de91685b9f;tab=manifest?project=vegas-codelab-5.
	wantBase64Sigs := []string{"MEUCIQDgoiwMiVl1SAI1iePhH6Oeqztms3IwNtN+w0P92HTqQgIgKjJNcHEy0Ep4g4MH1Vd0gAHvbwH9ahD+jlnMP/rXSGE="}
	if !cmp.Equal(gotBase64Sigs, wantBase64Sigs) {
		t.Errorf("signatures did not return expected base64 signatures, got %v, want %v", gotBase64Sigs, wantBase64Sigs)
	}
}

func createTestClient(t *testing.T, originalImageDesc v1.Descriptor) *Client {
	t.Helper()

	containerdClient, err := containerd.New(defaults.DefaultAddress)
	if err != nil {
		t.Skipf("test needs containerd daemon: %v", err)
	}
	t.Cleanup(func() { containerdClient.Close() })
	return &Client{
		cdClient:          containerdClient,
		OriginalImageDesc: originalImageDesc,
	}
}
