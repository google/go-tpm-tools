// Package client contains functionalities to discover container image signatures.
package client

import (
	"context"
	"fmt"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/images"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

const signatureTagSuffix = "sig"

// Client is a wrapper of containerd.Client to interact with signed image manifest.
type Client struct {
	cdClient      *containerd.Client
	OriginalImage containerd.Image
	RemoteOpts    []containerd.RemoteOpt
}

// New creates a new client.
func New(cdClient *containerd.Client, originalImage containerd.Image, opts ...containerd.RemoteOpt) *Client {
	c := &Client{
		cdClient:      cdClient,
		OriginalImage: originalImage,
		RemoteOpts:    opts,
	}
	return c
}

// FetchSignedImageManifest fetches a signed image manifest using a tag-based discovery mechanism.
func (c *Client) FetchSignedImageManifest(ctx context.Context, targetRepository string) (v1.Manifest, error) {
	image, err := c.pullTargetImage(ctx, targetRepository)
	if err != nil {
		return v1.Manifest{}, err
	}
	return getManifest(ctx, image)
}

func (c *Client) pullTargetImage(ctx context.Context, targetRepository string) (containerd.Image, error) {
	targetImageRef := fmt.Sprint(targetRepository, ":", formatSigTag(c.OriginalImage))
	image, err := c.cdClient.Pull(ctx, targetImageRef, c.RemoteOpts...)
	if err != nil {
		return nil, fmt.Errorf("[signature-discovery]: cannot pull the image [%s] from taregetRepository [%s]: %w", targetImageRef, targetRepository, err)
	}
	return image, nil
}

// formatSigTag turns image digests into tags with signatureTagSuffix:
// sha256:9ecc53c2 -> sha256-9ecc53c2.sig
func formatSigTag(image containerd.Image) string {
	digest := image.Target().Digest
	return fmt.Sprint(digest.Algorithm(), "-", digest.Encoded(), ".", signatureTagSuffix)
}

func getManifest(ctx context.Context, image containerd.Image) (v1.Manifest, error) {
	cs := image.ContentStore()
	manifest, err := images.Manifest(ctx, cs, image.Target(), image.Platform())
	if err != nil {
		return v1.Manifest{}, err
	}
	return manifest, nil
}
