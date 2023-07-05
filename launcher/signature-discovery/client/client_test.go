package client

import (
	"context"
	"testing"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/defaults"
	"github.com/containerd/containerd/namespaces"
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
	containerdClient, err := containerd.New(defaults.DefaultAddress)
	if err != nil {
		t.Skipf("test needs containerd daemon: %v", err)
	}
	defer containerdClient.Close()

	targetRepository := "gcr.io/distroless/static"
	originalImageDesc := v1.Descriptor{Digest: "sha256:9ecc53c269509f63c69a266168e4a687c7eb8c0cfd753bd8bfcaa4f58a90876f"}
	client := New(containerdClient, originalImageDesc)
	// testing image manifest fetching using a public docker repo url
	if _, err := client.FetchSignedImageManifest(ctx, targetRepository); err != nil {
		t.Errorf("failed to fetch signed image manifest from targetRepository [%s]: %v", targetRepository, err)
	}
}
