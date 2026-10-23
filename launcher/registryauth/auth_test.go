package registryauth

import (
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

const saToken = "sa-token"

// fakeRegistry records the host of each request. It returns 401 until the
// request has a bearer token from token.invalid. It also records whether a
// token request carried the service account token.
type fakeRegistry struct {
	hosts       []string
	sentSAToken bool
}

func (f *fakeRegistry) RoundTrip(req *http.Request) (*http.Response, error) {
	f.hosts = append(f.hosts, req.URL.Host)
	resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: http.NoBody, Request: req}
	switch {
	case req.URL.Host == "token.invalid":
		if containsSAToken(req) {
			f.sentSAToken = true
		}
		resp.Body = io.NopCloser(strings.NewReader(`{"token":"t","access_token":"t"}`))
	case req.Header.Get("Authorization") != "Bearer t":
		resp.StatusCode = http.StatusUnauthorized
		resp.Header.Set("WWW-Authenticate", `Bearer realm="https://token.invalid/token"`)
	default:
		resp.Header.Set("Docker-Content-Digest", "sha256:0000000000000000000000000000000000000000000000000000000000000000")
	}
	return resp, nil
}

// containsSAToken reports whether the token request sends the service account
// token, either as basic auth or in the OAuth form body.
func containsSAToken(req *http.Request) bool {
	if auth, ok := strings.CutPrefix(req.Header.Get("Authorization"), "Basic "); ok {
		if creds, err := base64.StdEncoding.DecodeString(auth); err == nil && strings.Contains(string(creds), saToken) {
			return true
		}
	}
	if req.Body == nil {
		return false
	}
	body, err := io.ReadAll(req.Body)
	return err == nil && strings.Contains(string(body), saToken)
}

// Hosts of the registries that Confidential Space supports for workload images.
var googleRegistryHosts = []string{
	// Container Registry.
	"gcr.io",
	"us.gcr.io",
	"eu.gcr.io",
	"asia.gcr.io",
	// Artifact Registry multi-region locations.
	"us-docker.pkg.dev",
	"europe-docker.pkg.dev",
	"asia-docker.pkg.dev",
	// Artifact Registry regional locations.
	"us-west1-docker.pkg.dev",
	"europe-west4-docker.pkg.dev",
	"asia-northeast1-docker.pkg.dev",
}

func TestIsGoogleRegistry(t *testing.T) {
	for _, host := range googleRegistryHosts {
		if !isGoogleRegistry(host) {
			t.Errorf("isGoogleRegistry(%q) = false, want true", host)
		}
	}
	for _, host := range []string{
		"pkg.dev",
		"notpkg.dev",
		"notgcr.io",
		"evilgcr.io",
		"gcr.io.",
		"gcr.io:443",
		"us-docker.pkg.dev:443",
		"gcr.io.example.com",
		"docker.pkg.dev.example.com",
		"registry.example.com",
		"docker.io",
		"ghcr.io",
	} {
		if isGoogleRegistry(host) {
			t.Errorf("isGoogleRegistry(%q) = true, want false", host)
		}
	}
}

func TestResolverUsesCorrectClient(t *testing.T) {
	type testCase struct {
		ref    string
		google bool
	}
	var tests []testCase
	for _, host := range googleRegistryHosts {
		tests = append(tests, testCase{ref: host + "/project/repo/image:latest", google: true})
	}
	tests = append(tests,
		testCase{ref: "registry.example.com/image:latest"},
		testCase{ref: "ghcr.io/owner/image:latest"},
	)
	for _, tc := range tests {
		t.Run(tc.ref, func(t *testing.T) {
			googleRegistry := &fakeRegistry{}
			defaultRegistry := &fakeRegistry{}
			// containerd uses http.DefaultClient when no client is set.
			origTransport := http.DefaultClient.Transport
			http.DefaultClient.Transport = defaultRegistry
			t.Cleanup(func() { http.DefaultClient.Transport = origTransport })

			resolver := Resolver(saToken, &http.Client{Transport: googleRegistry})
			if _, _, err := resolver.Resolve(t.Context(), tc.ref); err != nil {
				t.Fatalf("Resolve(%q) failed: %v", tc.ref, err)
			}

			host, _, _ := strings.Cut(tc.ref, "/")
			wantHosts := []string{host, "token.invalid", host}
			used, unused := googleRegistry, defaultRegistry
			if !tc.google {
				used, unused = defaultRegistry, googleRegistry
			}
			if diff := cmp.Diff(wantHosts, used.hosts); diff != "" {
				t.Errorf("Resolve(%q) hosts on expected client mismatch (-want +got):\n%s", tc.ref, diff)
			}
			if len(unused.hosts) != 0 {
				t.Errorf("Resolve(%q) sent requests on the other client: %v", tc.ref, unused.hosts)
			}
			if googleRegistry.sentSAToken != tc.google {
				t.Errorf("Resolve(%q) sent service account token on Google client = %v, want %v", tc.ref, googleRegistry.sentSAToken, tc.google)
			}
			if defaultRegistry.sentSAToken {
				t.Errorf("Resolve(%q) sent service account token on default client", tc.ref)
			}
		})
	}
}
