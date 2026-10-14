package launcher

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-tpm-tools/launcher/spec"
	"github.com/google/go-tpm-tools/verifier"
	"golang.org/x/oauth2"
)

func TestCreateAttestClients_Behaviors(t *testing.T) {
	certPool := x509.NewCertPool()
	pinnedTransport := http.DefaultTransport.(*http.Transport).Clone()
	pinnedTransport.TLSClientConfig = &tls.Config{RootCAs: certPool}
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
			name: "GCA REST mode fails when HTTP client has nil transport",
			launchSpec: spec.LaunchSpec{
				GcaAddress:        failingGcaServer.URL,
				ProjectID:         "test-project",
				Region:            "us-central1",
				DisableGcaRefresh: false,
			},
			googleClient: &http.Client{Transport: nil},
			wantErr:      true,
			errContains:  "googleClient must be non-nil with a valid transport",
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
					t.Fatalf("createAttestClients() error = %v, want error containing %q", err, tc.errContains)
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

func TestListenUnixSocket(t *testing.T) {
	sockDir := t.TempDir()
	sockPath := path.Join(sockDir, "test.sock")

	nl, err := listenUnixSocket(sockPath)
	if err != nil {
		t.Fatalf("listenUnixSocket(%q) error = %v, want nil", sockPath, err)
	}
	defer nl.Close()

	info, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("os.Stat(%q) error = %v, want nil", sockPath, err)
	}
	if perm := info.Mode().Perm(); perm != 0777 {
		t.Errorf("socket %s has permissions %04o, want 0777", sockPath, perm)
	}
}

func TestVerifySocketPermissions(t *testing.T) {
	tests := []struct {
		name    string
		mode    os.FileMode
		wantErr bool
	}{
		{
			name:    "valid 0777 permissions",
			mode:    0777,
			wantErr: false,
		},
		{
			name:    "invalid 0644 permissions",
			mode:    0644,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			sockPath := path.Join(tmpDir, "test.sock")
			if err := os.WriteFile(sockPath, []byte(""), tc.mode); err != nil {
				t.Fatalf("failed to create test file: %v", err)
			}
			if err := os.Chmod(sockPath, tc.mode); err != nil {
				t.Fatalf("failed to chmod test file: %v", err)
			}

			err := verifySocketPermissions(sockPath)
			if (err != nil) != tc.wantErr {
				t.Errorf("verifySocketPermissions(%q) error = %v, wantErr = %v", sockPath, err, tc.wantErr)
			}
		})
	}
}

func TestSetupBCSocketPermissions(_ *testing.T) {
	logger := &fakeLogger{}
	oldTimeout := bcSocketWaitTimeout
	bcSocketWaitTimeout = 0
	defer func() { bcSocketWaitTimeout = oldTimeout }()
	// Verify that setupBCSocketPermissions executes without panicking even when host sockets do not exist.
	setupBCSocketPermissions(logger)
}

// errorRecordingLogger records Error calls; fakeLogger drops them.
type errorRecordingLogger struct {
	fakeLogger
	mu     sync.Mutex
	errors []string
}

func (l *errorRecordingLogger) Error(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.errors = append(l.errors, formatLog(msg, args...))
}

// listenUnixWithMode creates a Unix socket and sets its mode, like the WSD
// agent does.
func listenUnixWithMode(t *testing.T, socketPath string, mode os.FileMode) {
	t.Helper()
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Errorf("net.Listen(%q) error = %v", socketPath, err)
		return
	}
	t.Cleanup(func() { l.Close() })
	if err := os.Chmod(socketPath, mode); err != nil {
		t.Errorf("os.Chmod(%q) error = %v", socketPath, err)
	}
}

func TestSetupSocketPermissionsWaitsForLateSockets(t *testing.T) {
	dir := t.TempDir()
	created := make(chan struct{})
	// Simulates wsd.service creating its sockets (0755, like WSD images older
	// than key-protection-module 48d5ea8) after the launcher has started.
	go func() {
		defer close(created)
		time.Sleep(300 * time.Millisecond)
		listenUnixWithMode(t, path.Join(dir, keyManagerSocket), 0755)
		listenUnixWithMode(t, path.Join(dir, keyManagerGrpcSocket), 0755)
	}()

	logger := &errorRecordingLogger{}
	setupSocketPermissions(logger, dir, 10*time.Second)
	<-created

	if len(logger.errors) != 0 {
		t.Errorf("setupSocketPermissions() logged errors: %v, want none", logger.errors)
	}
	for _, name := range []string{keyManagerSocket, keyManagerGrpcSocket} {
		if err := verifySocketPermissions(path.Join(dir, name)); err != nil {
			t.Errorf("verifySocketPermissions(%q) = %v, want nil", name, err)
		}
	}
}

func TestSetupSocketPermissionsTimesOut(t *testing.T) {
	logger := &errorRecordingLogger{}
	start := time.Now()
	setupSocketPermissions(logger, t.TempDir(), 200*time.Millisecond)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("setupSocketPermissions() took %v, want about 200ms", elapsed)
	}
	if len(logger.errors) != 2 {
		t.Fatalf("setupSocketPermissions() logged %d errors (%v), want 2", len(logger.errors), logger.errors)
	}
	for _, e := range logger.errors {
		if !strings.Contains(e, "WSD socket is not available") || strings.Contains(e, "BADKEY") {
			t.Errorf("unexpected error log %q", e)
		}
	}
}

func TestWaitForSocketRejectsRegularFile(t *testing.T) {
	p := path.Join(t.TempDir(), keyManagerSocket)
	if err := os.WriteFile(p, nil, 0777); err != nil {
		t.Fatal(err)
	}
	if err := waitForSocket(p, time.Now().Add(200*time.Millisecond)); err == nil {
		t.Errorf("waitForSocket(%q) = nil for a regular file, want error", p)
	}
}

