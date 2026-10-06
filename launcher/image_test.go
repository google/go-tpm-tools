package launcher

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/containerd/containerd"
	"github.com/google/go-tpm-tools/launcher/spec"
	"golang.org/x/oauth2"
)

func TestPullImageWithRetries(t *testing.T) {
	testCases := []struct {
		name        string
		imagePuller func(int) (containerd.Image, error)
		wantPass    bool
	}{
		{
			name: "success with single attempt",
			imagePuller: func(int) (containerd.Image, error) {
				return &fakeImage{}, nil
			},
			wantPass: true,
		},
		{
			name: "failure then success",
			imagePuller: func(attempts int) (containerd.Image, error) {
				if attempts%2 == 1 {
					return nil, errors.New("fake error")
				}
				return &fakeImage{}, nil
			},
			wantPass: true,
		},
		{
			name: "failure with attempts exceeded",
			imagePuller: func(int) (containerd.Image, error) {
				return nil, errors.New("fake error")
			},
			wantPass: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				retryPolicy := func() backoff.BackOff {
					b := backoff.NewExponentialBackOff()
					return backoff.WithMaxRetries(b, 2)
				}

				attempts := 0
				_, err := pullImageWithRetries(
					func() (containerd.Image, error) {
						attempts++
						return tc.imagePuller(attempts)
					},
					retryPolicy,
				)
				if gotPass := (err == nil); gotPass != tc.wantPass {
					t.Errorf("pullImageWithRetries failed, got %v, but want %v", gotPass, tc.wantPass)
				}
			})
		})
	}
}

func TestInitImage_WithValidToken_Succeeds(t *testing.T) {
	ctx := t.Context()
	fakeCli := &fakeContainerdClient{
		pullResult: &fakeImage{},
	}
	validToken := oauth2.Token{
		AccessToken: "valid-token",
		Expiry:      time.Now().Add(time.Hour),
	}
	launchSpec := spec.LaunchSpec{
		ImageRef: "gcr.io/test/image:latest",
	}

	img, err := initImage(ctx, fakeCli, launchSpec, validToken, http.DefaultClient)
	if err != nil {
		t.Fatalf("initImage failed: %v", err)
	}
	if img == nil {
		t.Error("initImage returned nil image, want non-nil")
	}
}

func TestInitImage_WithNoToken_Succeeds(t *testing.T) {
	ctx := t.Context()
	fakeCli := &fakeContainerdClient{
		pullResult: &fakeImage{},
	}
	emptyToken := oauth2.Token{}
	launchSpec := spec.LaunchSpec{
		ImageRef: "docker.io/library/hello-world:latest",
	}

	img, err := initImage(ctx, fakeCli, launchSpec, emptyToken, http.DefaultClient)
	if err != nil {
		t.Fatalf("initImage failed: %v", err)
	}
	if img == nil {
		t.Error("initImage returned nil image, want non-nil")
	}
}

func TestInitImage_WithToken_PropagatesAuthError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()
		fakeCli := &fakeContainerdClient{
			pullErr: errors.New("auth failure"),
		}
		validToken := oauth2.Token{
			AccessToken: "valid-token",
			Expiry:      time.Now().Add(time.Hour),
		}
		launchSpec := spec.LaunchSpec{
			ImageRef: "gcr.io/test/image:latest",
		}

		_, err := initImage(ctx, fakeCli, launchSpec, validToken, http.DefaultClient)
		if err == nil {
			t.Fatal("initImage succeeded, want error")
		}
		wantErrSubstr := "cannot pull the image: failed to pull image with retries"
		if !strings.Contains(err.Error(), wantErrSubstr) {
			t.Errorf("initImage error = %q, want substring %q", err.Error(), wantErrSubstr)
		}
	})
}

func TestInitImage_NoToken_PropagatesPublicError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()
		fakeCli := &fakeContainerdClient{
			pullErr: errors.New("image not found"),
		}
		emptyToken := oauth2.Token{}
		launchSpec := spec.LaunchSpec{
			ImageRef: "docker.io/library/hello-world:latest",
		}

		_, err := initImage(ctx, fakeCli, launchSpec, emptyToken, http.DefaultClient)
		if err == nil {
			t.Fatal("initImage succeeded, want error")
		}
		wantErrSubstr := "cannot pull the image (no token, only works for a public image): failed to pull image with retries"
		if !strings.Contains(err.Error(), wantErrSubstr) {
			t.Errorf("initImage error = %q, want substring %q", err.Error(), wantErrSubstr)
		}
	})
}
