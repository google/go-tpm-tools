package client

import (
	"context"
	"fmt"
	"testing"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/defaults"
	"github.com/containerd/containerd/namespaces"
)

func pullPublicImage(ctx context.Context, imageRef string, cdClient *containerd.Client) (containerd.Image, error) {
	image, err := cdClient.Pull(ctx, imageRef, containerd.WithPullUnpack)
	if err != nil {
		return nil, fmt.Errorf("cannot pull the image (no token, only works for a public image): %w", err)
	}
	return image, nil
}
func TestFormatSigTag(t *testing.T) {
	ctx := namespaces.WithNamespace(context.Background(), "test")
	containerdClient, err := containerd.New(defaults.DefaultAddress)
	if err != nil {
		t.Skipf("test needs containerd daemon: %v", err)
	}
	defer containerdClient.Close()

	testCases := []struct {
		name        string
		originalRef string
		wantSigTag  string
		wantPass    bool
	}{
		{
			name:        "formatSigTag success",
			originalRef: "gcr.io/distroless/static:nonroot",
			wantSigTag:  "sha256-9ecc53c269509f63c69a266168e4a687c7eb8c0cfd753bd8bfcaa4f58a90876f.sig",
			wantPass:    true,
		},
		{
			name:        "formatSigTag failed with wrong image digest",
			originalRef: "gcr.io/distroless/static:nonroot",
			wantSigTag:  "sha256-18740b995b4eac1b5706392a96ff8c4f30cefac18772058a71449692f1581f0f.sig",
			wantPass:    false,
		},
		{
			name:        "formatSigTag failed with wrong tag format",
			originalRef: "gcr.io/distroless/static:nonroot",
			wantSigTag:  "sha256@9ecc53c269509f63c69a266168e4a687c7eb8c0cfd753bd8bfcaa4f58a90876f.sig",
			wantPass:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			originalImage, err := pullPublicImage(ctx, tc.originalRef, containerdClient)
			if err != nil {
				t.Fatalf("failed to pull public image ref [%s]: %v", tc.originalRef, err)
			}
			if got := formatSigTag(originalImage) == tc.wantSigTag; got != tc.wantPass {
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

	originalImageRef := "gcr.io/distroless/static:nonroot"
	targetRepository := "gcr.io/distroless/static"
	originalImage, err := pullPublicImage(ctx, originalImageRef, containerdClient)
	if err != nil {
		t.Fatalf("failed to pull public image ref [%s]: %v", originalImageRef, err)
	}

	client := New(containerdClient, originalImage)
	// testing image manifest fetching using a public docker repo url
	if _, err := client.FetchSignedImageManifest(ctx, targetRepository); err != nil {
		t.Errorf("failed to fetch signed image manifest from targetRepository [%s]: %v", targetRepository, err)
	}
}
