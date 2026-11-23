package gpu

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/go-tpm-tools/launcher/internal/logging"
)

const testContent = "artifact content"

func testDigest() string {
	sum := sha256.Sum256([]byte(testContent))
	return hex.EncodeToString(sum[:])
}

func newArtifactServer(t *testing.T, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		w.Write([]byte(testContent))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testBackoffPolicy() backoff.BackOff {
	return backoff.WithMaxRetries(&backoff.ZeroBackOff{}, 3)
}

func TestDownloadVerifyMatchingDigestWritesFile(t *testing.T) {
	srv := newArtifactServer(t, http.StatusOK)
	dst := filepath.Join(t.TempDir(), "a.run")

	err := downloadVerify(t.Context(), srv.Client(), srv.URL, dst, testDigest())

	if err != nil {
		t.Fatalf("downloadVerify() error = %v, want nil", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	if string(got) != testContent {
		t.Errorf("downloaded content = %q, want %q", got, testContent)
	}
}

func TestDownloadVerifyDigestMismatchFails(t *testing.T) {
	srv := newArtifactServer(t, http.StatusOK)
	wrongDigest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	err := downloadVerify(t.Context(), srv.Client(), srv.URL, filepath.Join(t.TempDir(), "a.run"), wrongDigest)

	if err == nil {
		t.Error("downloadVerify() error = nil, want digest mismatch")
	}
}

func TestDownloadVerifyEmptyDigestFails(t *testing.T) {
	srv := newArtifactServer(t, http.StatusOK)
	dst := filepath.Join(t.TempDir(), "a.run")

	err := downloadVerify(t.Context(), srv.Client(), srv.URL, dst, "")

	if err == nil {
		t.Error("downloadVerify() error = nil, want error for missing digest")
	}
	if _, statErr := os.Stat(dst); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("os.Stat() error = %v, want os.ErrNotExist", statErr)
	}
}

func TestDownloadWritesFile(t *testing.T) {
	srv := newArtifactServer(t, http.StatusOK)
	dst := filepath.Join(t.TempDir(), "a.bin")

	gotDigest, err := download(t.Context(), srv.Client(), srv.URL, dst)

	if err != nil {
		t.Fatalf("download() error = %v, want nil", err)
	}
	if gotDigest != testDigest() {
		t.Errorf("download() digest = %q, want %q", gotDigest, testDigest())
	}
	if _, err := os.Stat(dst); err != nil {
		t.Errorf("os.Stat() error = %v, want nil", err)
	}
}

func TestDownloadNonOKStatusFails(t *testing.T) {
	srv := newArtifactServer(t, http.StatusNotFound)

	_, err := download(t.Context(), srv.Client(), srv.URL, filepath.Join(t.TempDir(), "a.bin"))

	if err == nil {
		t.Error("download() error = nil, want error for status 404")
	}
}

func TestRetryDownloadRetriesTransientErrors(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(testContent))
	}))
	t.Cleanup(srv.Close)
	dst := filepath.Join(t.TempDir(), "a.run")

	err := retryDownload(t.Context(), logging.NullLogger(), "a.run", time.Second, testBackoffPolicy, func(ctx context.Context) error {
		return downloadVerify(ctx, srv.Client(), srv.URL, dst, testDigest())
	})

	if err != nil {
		t.Fatalf("retryDownload() error = %v, want nil", err)
	}
	if got := attempts.Load(); got != 2 {
		t.Errorf("attempts = %d, want 2", got)
	}
}

func TestRetryDownloadDoesNotRetryPermanentErrors(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	dst := filepath.Join(t.TempDir(), "a.run")

	err := retryDownload(t.Context(), logging.NullLogger(), "a.run", time.Second, testBackoffPolicy, func(ctx context.Context) error {
		return downloadVerify(ctx, srv.Client(), srv.URL, dst, testDigest())
	})

	if err == nil {
		t.Error("retryDownload() error = nil, want error for status 404")
	}
	if got := attempts.Load(); got != 1 {
		t.Errorf("attempts = %d, want 1", got)
	}
}

func TestRetryDownloadPerAttemptTimeoutRetries(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			<-r.Context().Done()
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(testContent))
	}))
	t.Cleanup(srv.Close)
	dst := filepath.Join(t.TempDir(), "a.run")

	err := retryDownload(t.Context(), logging.NullLogger(), "a.run", 50*time.Millisecond, testBackoffPolicy, func(ctx context.Context) error {
		return downloadVerify(ctx, srv.Client(), srv.URL, dst, testDigest())
	})

	if err != nil {
		t.Fatalf("retryDownload() error = %v, want nil", err)
	}
	if got := attempts.Load(); got != 2 {
		t.Errorf("attempts = %d, want 2", got)
	}
}

func TestReadBuildID(t *testing.T) {
	osRelease := filepath.Join(t.TempDir(), "os-release")
	if err := os.WriteFile(osRelease, []byte("NAME=\"Container-Optimized OS\"\nBUILD_ID=19216.760.8\nID=cos\n"), 0644); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	got, err := readBuildID(osRelease)

	if err != nil {
		t.Fatalf("readBuildID() error = %v, want nil", err)
	}
	if got != "19216.760.8" {
		t.Errorf("readBuildID() = %q, want %q", got, "19216.760.8")
	}
}

func TestReadBuildIDMissingFails(t *testing.T) {
	osRelease := filepath.Join(t.TempDir(), "os-release")
	if err := os.WriteFile(osRelease, []byte("ID=cos\n"), 0644); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	if _, err := readBuildID(osRelease); err == nil {
		t.Error("readBuildID() error = nil, want error for missing BUILD_ID")
	}
}

func TestReadBuildIDMissingFileFails(t *testing.T) {
	if _, err := readBuildID(filepath.Join(t.TempDir(), "os-release")); err == nil {
		t.Error("readBuildID() error = nil, want error for missing file")
	}
}

func TestStageArtifactsCreatesDirAndDownloadsAll(t *testing.T) {
	var mu sync.Mutex
	var gotPaths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotPaths = append(gotPaths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(testContent))
	}))
	t.Cleanup(srv.Close)
	dir := filepath.Join(t.TempDir(), "staging")

	err := stageArtifacts(t.Context(), srv.Client(), logging.NullLogger(), dir, srv.URL, "19216.760.8", testDigest(), testDigest(), time.Second, testBackoffPolicy)

	if err != nil {
		t.Fatalf("stageArtifacts() error = %v, want nil", err)
	}
	wantPaths := []string{
		"/cos-nvidia-gpu-drivers/NVIDIA-Linux-x86_64-595.58.03.run",
		"/cos-tools/19216.760.8/lakitu/nvidia-drivers-595.58.03.tgz",
		"/cos-tools/19216.760.8/lakitu/gpu_driver_versions.bin",
	}
	if !slices.Equal(gotPaths, wantPaths) {
		t.Errorf("requested paths = %v, want %v", gotPaths, wantPaths)
	}
	for _, name := range []string{NvDriverVer595_58_03Runfile, prebuiltModulesFile, driverVersionsFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("os.Stat(%s) error = %v, want nil", name, err)
		}
	}
}

func TestInstallerArgs(t *testing.T) {
	want := []string{
		"/cos-gpu-installer",
		"install",
		"-version=595.58.03",
		"-host-dir=/var/lib/nvidia",
		"--no-verify",
		"-local-artifacts-dir=/root/var/lib/nvidia-artifacts",
		"-use-regional-bucket=false",
	}

	if got := installerArgs(); !slices.Equal(got, want) {
		t.Errorf("installerArgs() = %v, want %v", got, want)
	}
}
