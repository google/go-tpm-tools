package launcher

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/containerd/containerd"
	"github.com/google/go-tpm-tools/launcher/registryauth"
	"github.com/google/go-tpm-tools/launcher/spec"
	"golang.org/x/oauth2"
)

func pullImageWithRetries(f func() (containerd.Image, error), retry func() backoff.BackOff) (containerd.Image, error) {
	var err error
	var image containerd.Image
	err = backoff.Retry(func() error {
		image, err = f()
		return err
	}, retry())
	if err != nil {
		return nil, fmt.Errorf("failed to pull image with retries, the last error is: %w", err)
	}
	return image, nil
}

func initImage(ctx context.Context, cdClient ContainerdClient, launchSpec spec.LaunchSpec, token oauth2.Token, googleClient *http.Client) (containerd.Image, error) {
	var accessToken string
	if token.Valid() {
		accessToken = token.AccessToken
	}

	remoteOpt := containerd.WithResolver(registryauth.Resolver(accessToken, googleClient))
	image, err := pullImageWithRetries(
		func() (containerd.Image, error) {
			return cdClient.Pull(ctx, launchSpec.ImageRef, containerd.WithPullUnpack, remoteOpt)
		},
		pullImageBackoffPolicy,
	)
	if err != nil {
		if accessToken != "" {
			return nil, fmt.Errorf("cannot pull the image: %w", err)
		}
		return nil, fmt.Errorf("cannot pull the image (no token, only works for a public image): %w", err)
	}
	return image, nil
}

func pullImageBackoffPolicy() backoff.BackOff {
	b := backoff.NewConstantBackOff(time.Millisecond * 500)
	return backoff.WithMaxRetries(b, 3)
}
