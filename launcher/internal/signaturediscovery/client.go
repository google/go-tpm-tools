// Package signaturediscovery contains functionalities to discover container image signatures.
package signaturediscovery

import (
	"context"
	"fmt"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/remotes"
	"github.com/google/go-tpm-tools/verifier/oci"
	"github.com/google/go-tpm-tools/verifier/oci/cosign"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

const signatureTagSuffix = "sig"

type (
	remoteResolverFetcher func(context.Context) (remotes.Resolver, error)
	imageFetcher          func(context.Context, string, ...containerd.RemoteOpt) (containerd.Image, error)
)

// Fetcher discovers and fetches OCI signatures from the target repository.
type Fetcher interface {
	FetchImageSignatures(ctx context.Context, targetRepository string) ([]oci.Signature, error)
}

// Client is a wrapper of containerd.Client to interact with signed image manifest.
type Client struct {
	OriginalImageDesc v1.Descriptor
	refreshResolver   remoteResolverFetcher
	imageFetcher      imageFetcher
}

// New creates a new client that implements Fetcher interface.
func New(originalImageDesc v1.Descriptor, resolverFetcher remoteResolverFetcher, imageFetcher imageFetcher) Fetcher {
	return &Client{
		OriginalImageDesc: originalImageDesc,
		refreshResolver:   resolverFetcher,
		imageFetcher:      imageFetcher,
	}
}

// FetchSignedImageManifest fetches a signed image manifest using a tag-based discovery mechanism.
func (c *Client) FetchSignedImageManifest(ctx context.Context, targetRepository string) (v1.Manifest, error) {
	image, err := c.pullSignatureImage(ctx, targetRepository)
	if err != nil {
		return v1.Manifest{}, err
	}
	return getManifest(ctx, image)
}

// FetchImageSignatures returns a list of valid image signatures associated with the target OCI image.
func (c *Client) FetchImageSignatures(ctx context.Context, targetRepository string) ([]oci.Signature, error) {
	image, err := c.pullSignatureImage(ctx, targetRepository)
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

func (c *Client) pullSignatureImage(ctx context.Context, signatureRepository string) (containerd.Image, error) {
	signatureImageRef := fmt.Sprint(signatureRepository, ":", formatSigTag(c.OriginalImageDesc))

	// Pull signature image from a public repository.
	if c.refreshResolver == nil {
		return c.imageFetcher(ctx, signatureImageRef)
	}

	// Refresh resolver before pulling container image.
	resolver, err := c.refreshResolver(ctx)
	if err == nil {
		return c.imageFetcher(ctx, signatureImageRef, containerd.WithResolver(resolver))
	}
	return nil, fmt.Errorf("failed to refresh remote resolver before pulling container image: %v", err)
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
