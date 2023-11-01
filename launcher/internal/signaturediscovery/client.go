// Package signaturediscovery contains functionalities to discover container image signatures.
package signaturediscovery

import (
	"context"
	"fmt"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images"
	"github.com/google/go-tpm-tools/launcher/internal/oci"
	"github.com/google/go-tpm-tools/launcher/internal/oci/cosign"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

const signatureTagSuffix = "sig"

// Fetcher discovers and fetches OCI signatures from the target repository.
type Fetcher interface {
	FetchImageSignatures(ctx context.Context, targetRepository string) ([]oci.Signature, error)
}

// Client is a wrapper of containerd.Client to interact with signed image manifest.
type Client struct {
	cdClient          *containerd.Client
	OriginalImageDesc v1.Descriptor
	RemoteOpts        []containerd.RemoteOpt
}

// New creates a new client that implements Fetcher interface.
func New(cdClient *containerd.Client, originalImageDesc v1.Descriptor, opts ...containerd.RemoteOpt) Fetcher {
	return &Client{
		cdClient:          cdClient,
		OriginalImageDesc: originalImageDesc,
		RemoteOpts:        opts,
	}
}

// FetchSignedImageManifest fetches a signed image manifest using a tag-based discovery mechanism.
func (c *Client) FetchSignedImageManifest(ctx context.Context, targetRepository string) (v1.Manifest, error) {
	image, err := c.pullTargetImage(ctx, targetRepository)
	if err != nil {
		return v1.Manifest{}, err
	}
	return getManifest(ctx, image)
}

// FetchImageSignatures returns a list of valid image signatures associated with the target OCI image.
func (c *Client) FetchImageSignatures(ctx context.Context, targetRepository string) ([]oci.Signature, error) {
	image, err := c.pullTargetImage(ctx, targetRepository)
	if err != nil {
		return nil, err
	}
	manifest, err := getManifest(ctx, image)
	if err != nil {
		return nil, err
	}
	signatures := make([]oci.Signature, 0, len(manifest.Layers))
	for _, layer := range manifest.Layers {
		blob, err := content.ReadBlob(ctx, image.ContentStore(), layer)
		if err != nil {
			return nil, err
		}
		sig := &cosign.Sig{
			Layer:      layer,
			Blob:       blob,
			SourceRepo: targetRepository,
		}
		signatures = append(signatures, sig)
	}
	return signatures, nil
}

func (c *Client) pullTargetImage(ctx context.Context, targetRepository string) (containerd.Image, error) {
	targetImageRef := fmt.Sprint(targetRepository, ":", formatSigTag(c.OriginalImageDesc))
	image, err := c.cdClient.Pull(ctx, targetImageRef, c.RemoteOpts...)
	if err != nil {
		return nil, fmt.Errorf("cannot pull the signature object [%s] from target repository [%s]: %w", targetImageRef, targetRepository, err)
	}
	return image, nil
}

// formatSigTag turns image digests into tags with signatureTagSuffix:
// sha256:9ecc53c2 -> sha256-9ecc53c2.sig
func formatSigTag(imageDesc v1.Descriptor) string {
	digest := imageDesc.Digest
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
