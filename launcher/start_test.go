package launcher

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-tpm-tools/launcher/spec"
	"github.com/google/go-tpm-tools/verifier"
	"golang.org/x/oauth2"
)

func TestCreateAttestClients_Behaviors(t *testing.T) {
	certPool := x509.NewCertPool()
	pinnedTransport := http.DefaultTransport.(*http.Transport).Clone()
	pinnedTransport.TLSClientConfig = &tls.Config{RootCAs: certPool}
	unauthenticatedPinnedClient := &http.Client{Transport: pinnedTransport}

	unpinnedOAuthClient := &http.Client{
		Transport: &oauth2.Transport{
			Source: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "fake-test-token"}),
			Base:   http.DefaultTransport,
		},
	}

	validAuthenticatedAndPinnedClient := &http.Client{
		Transport: &oauth2.Transport{
			Source: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "fake-test-token"}),
			Base:   pinnedTransport,
		},
	}

	// Local hermetic mock HTTP server simulating GCA location endpoints
	gcaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"name": "projects/test-project/locations/us-central1"}`)
	}))
	defer gcaServer.Close()

	// Local hermetic mock HTTP server simulating 401 Unauthorized GCA endpoint
	failingGcaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, `{"error": {"code": 401, "message": "Request is missing required authentication credential."}}`)
	}))
	defer failingGcaServer.Close()

	tests := []struct {
		name          string
		launchSpec    spec.LaunchSpec
		googleClient  *http.Client
		wantErr       bool
		errContains   string
		wantGCANotNil bool
		wantITANotNil bool
	}{
		{
			name: "Fake verifier mode sets fake GCA and ITA clients",
			launchSpec: spec.LaunchSpec{
				FakeVerifierEnabled: true,
			},
			googleClient:  validAuthenticatedAndPinnedClient,
			wantGCANotNil: true,
			wantITANotNil: true,
		},
		{
			name: "ITA mode returns error on invalid region/config",
			launchSpec: spec.LaunchSpec{
				ITAConfig: verifier.ITAConfig{
					ITARegion: "invalid-region-config",
				},
			},
			googleClient: validAuthenticatedAndPinnedClient,
			wantErr:      true,
			errContains:  "failed to create ITA client",
		},
		{
			name: "GCA REST mode succeeds when valid clientOpts passed",
			launchSpec: spec.LaunchSpec{
				GcaAddress: gcaServer.URL,
				ProjectID:  "test-project",
				Region:     "us-central1",
			},
			googleClient:  validAuthenticatedAndPinnedClient,
			wantGCANotNil: true,
		},
		{
			name: "GCA REST mode fails when DisableGcaRefresh is false and auth fails",
			launchSpec: spec.LaunchSpec{
				GcaAddress:        failingGcaServer.URL,
				ProjectID:         "test-project",
				Region:            "us-central1",
				DisableGcaRefresh: false,
			},
			googleClient: validAuthenticatedAndPinnedClient,
			wantErr:      true,
			errContains:  "failed to create REST verifier client",
		},
		{
			name: "GCA REST mode suppresses failure when DisableGcaRefresh is true",
			launchSpec: spec.LaunchSpec{
				GcaAddress:        failingGcaServer.URL,
				ProjectID:         "test-project",
				Region:            "us-central1",
				DisableGcaRefresh: true,
			},
			googleClient:  validAuthenticatedAndPinnedClient,
			wantErr:       false,
			wantGCANotNil: false, // GCA client set to nil gracefully
		},
		{
			name: "GCA REST mode fails when HTTP client is nil",
			launchSpec: spec.LaunchSpec{
				GcaAddress:        failingGcaServer.URL,
				ProjectID:         "test-project",
				Region:            "us-central1",
				DisableGcaRefresh: false,
			},
			googleClient: nil,
			wantErr:      true,
			errContains:  "googleClient must be non-nil",
		},
		{
			name: "GCA REST mode fails when HTTP client is missing OAuth2 token credentials",
			launchSpec: spec.LaunchSpec{
				GcaAddress:        failingGcaServer.URL,
				ProjectID:         "test-project",
				Region:            "us-central1",
				DisableGcaRefresh: false,
			},
			googleClient: unauthenticatedPinnedClient,
			wantErr:      true,
			errContains:  "missing OAuth2 token credentials",
		},
		{
			name: "GCA REST mode fails when HTTP client is missing Google Root CA certificate pinning",
			launchSpec: spec.LaunchSpec{
				GcaAddress:        failingGcaServer.URL,
				ProjectID:         "test-project",
				Region:            "us-central1",
				DisableGcaRefresh: false,
			},
			googleClient: unpinnedOAuthClient,
			wantErr:      true,
			errContains:  "missing pinned Google Root CAs",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger := &fakeLogger{}
			clients, err := createAttestClients(t.Context(), tc.launchSpec, logger, tc.googleClient)

			if (err != nil) != tc.wantErr {
				t.Fatalf("createAttestClients() error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr && tc.errContains != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("expected error containing %q, got %v", tc.errContains, err)
				}
			}
			if tc.wantGCANotNil && clients.GCA == nil {
				t.Error("expected GCA client to be non-nil")
			}
			if !tc.wantGCANotNil && clients.GCA != nil {
				t.Error("expected GCA client to be nil")
			}
			if tc.wantITANotNil && clients.ITA == nil {
				t.Error("expected ITA client to be non-nil")
			}
		})
	}
}
