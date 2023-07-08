// Package client contains functionalities to discover container image signatures.
package client

import (
	"context"
	"fmt"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images"
	"github.com/google/go-tpm-tools/launcher/signature-discovery/oci"
	"github.com/google/go-tpm-tools/launcher/signature-discovery/oci/cosign"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"go.uber.org/multierr"
)

const signatureTagSuffix = "sig"

var validSig = oci.ValidSig

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
	var validSigs []oci.Signature
	for _, layer := range manifest.Layers {
		blob, e := content.ReadBlob(ctx, image.ContentStore(), layer)
		if e != nil {
			err = multierr.Append(err, e)
			continue
		}
		sig := &cosign.Sig{
			Layer: layer,
			Blob:  blob,
		}
		if e := validSig(sig); e == nil {
			validSigs = append(validSigs, sig)
		} else {
			err = multierr.Append(err, e)
		}
	}
	return validSigs, err
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
