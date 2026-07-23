package launcher

import (
	"errors"
	"testing"

	"github.com/cenkalti/backoff/v4"
	"github.com/containerd/containerd"
)

func TestPullImageWithRetries(t *testing.T) {
	testCases := []struct {
		name        string
		imagePuller func(int) (containerd.Image, error)
		wantPass    bool
	}{
		{
			name:        "success with single attempt",
			imagePuller: func(int) (containerd.Image, error) { return &fakeImage{}, nil },
			wantPass:    true,
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
				retryPolicy)
			if gotPass := (err == nil); gotPass != tc.wantPass {
				t.Errorf("pullImageWithRetries failed, got %v, but want %v", gotPass, tc.wantPass)
			}
		})
	}
}
