package registryauth

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// fakeRegistry records the host of each request. It returns 401 until the
// request has a bearer token from token.invalid.
type fakeRegistry struct {
	hosts []string
}

func (f *fakeRegistry) RoundTrip(req *http.Request) (*http.Response, error) {
	f.hosts = append(f.hosts, req.URL.Host)
	resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: http.NoBody, Request: req}
	switch {
	case req.URL.Host == "token.invalid":
		resp.Body = io.NopCloser(strings.NewReader(`{"token":"t","access_token":"t"}`))
	case req.Header.Get("Authorization") != "Bearer t":
		resp.StatusCode = http.StatusUnauthorized
		resp.Header.Set("WWW-Authenticate", `Bearer realm="https://token.invalid/token"`)
	default:
		resp.Header.Set("Docker-Content-Digest", "sha256:0000000000000000000000000000000000000000000000000000000000000000")
	}
	return resp, nil
}

func TestResolverUsesCorrectClient(t *testing.T) {
	tests := []struct {
		name             string
		ref              string
		wantGoogleHosts  []string
		wantDefaultHosts []string
	}{
		{
			name:            "gcr",
			ref:             "gcr.io/project/image:latest",
			wantGoogleHosts: []string{"gcr.io", "token.invalid", "gcr.io"},
		},
		{
			name:            "regional_gcr",
			ref:             "us.gcr.io/project/image:latest",
			wantGoogleHosts: []string{"us.gcr.io", "token.invalid", "us.gcr.io"},
		},
		{
			name:            "artifact_registry",
			ref:             "us-docker.pkg.dev/project/repo/image:latest",
			wantGoogleHosts: []string{"us-docker.pkg.dev", "token.invalid", "us-docker.pkg.dev"},
		},
		{
			name:             "non_google",
			ref:              "registry.example.com/image:latest",
			wantDefaultHosts: []string{"registry.example.com", "token.invalid", "registry.example.com"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			googleRegistry := &fakeRegistry{}
			defaultRegistry := &fakeRegistry{}
			// containerd uses http.DefaultClient when no client is set.
			origTransport := http.DefaultClient.Transport
			http.DefaultClient.Transport = defaultRegistry
			t.Cleanup(func() { http.DefaultClient.Transport = origTransport })

			resolver := Resolver("sa-token", &http.Client{Transport: googleRegistry})
			if _, _, err := resolver.Resolve(t.Context(), tc.ref); err != nil {
				t.Fatalf("Resolve(%q) failed: %v", tc.ref, err)
			}

			if diff := cmp.Diff(tc.wantGoogleHosts, googleRegistry.hosts); diff != "" {
				t.Errorf("Resolve(%q) Google client hosts mismatch (-want +got):\n%s", tc.ref, diff)
			}
			if diff := cmp.Diff(tc.wantDefaultHosts, defaultRegistry.hosts); diff != "" {
				t.Errorf("Resolve(%q) default client hosts mismatch (-want +got):\n%s", tc.ref, diff)
			}
		})
	}
}
