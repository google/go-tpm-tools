package gpu

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
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

func TestDownloadArtifactMatchingDigestWritesFile(t *testing.T) {
	srv := newArtifactServer(t, http.StatusOK)
	dir := t.TempDir()

	err := downloadArtifact(t.Context(), srv.Client(), dir, artifact{url: srv.URL, name: "a.run", digest: testDigest()})

	if err != nil {
		t.Fatalf("downloadArtifact() error = %v, want nil", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "a.run"))
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	if string(got) != testContent {
		t.Errorf("downloaded content = %q, want %q", got, testContent)
	}
}

func TestDownloadArtifactDigestMismatchFails(t *testing.T) {
	srv := newArtifactServer(t, http.StatusOK)
	wrongDigest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	err := downloadArtifact(t.Context(), srv.Client(), t.TempDir(), artifact{url: srv.URL, name: "a.run", digest: wrongDigest})

	if err == nil {
		t.Error("downloadArtifact() error = nil, want digest mismatch")
	}
}

func TestDownloadArtifactEmptyDigestSkipsCheck(t *testing.T) {
	srv := newArtifactServer(t, http.StatusOK)
	dir := t.TempDir()

	err := downloadArtifact(t.Context(), srv.Client(), dir, artifact{url: srv.URL, name: "a.bin"})

	if err != nil {
		t.Fatalf("downloadArtifact() error = %v, want nil", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "a.bin")); err != nil {
		t.Errorf("os.Stat() error = %v, want nil", err)
	}
}

func TestDownloadArtifactNonOKStatusFails(t *testing.T) {
	srv := newArtifactServer(t, http.StatusNotFound)

	err := downloadArtifact(t.Context(), srv.Client(), t.TempDir(), artifact{url: srv.URL, name: "a.bin"})

	if err == nil {
		t.Error("downloadArtifact() error = nil, want error for status 404")
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
	srv := newArtifactServer(t, http.StatusOK)
	dir := filepath.Join(t.TempDir(), "staging")

	err := stageArtifacts(t.Context(), srv.Client(), dir, []artifact{{url: srv.URL, name: "a.run"}, {url: srv.URL, name: "b.bin"}})

	if err != nil {
		t.Fatalf("stageArtifacts() error = %v, want nil", err)
	}
	for _, name := range []string{"a.run", "b.bin"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("os.Stat(%s) error = %v, want nil", name, err)
		}
	}
}

func TestInstallerArtifacts(t *testing.T) {
	got := installerArtifacts("https://example.com", "19216.760.8", "module-digest")

	want := []artifact{
		{url: "https://example.com/cos-nvidia-gpu-drivers/NVIDIA-Linux-x86_64-595.58.03.run", name: "NVIDIA-Linux-x86_64-595.58.03.run", digest: NvDriverVer595_58_03Digest},
		{url: "https://example.com/cos-tools/19216.760.8/lakitu/nvidia-drivers-595.58.03.tgz", name: "nvidia-drivers-595.58.03.tgz", digest: "module-digest"},
		{url: "https://example.com/cos-tools/19216.760.8/lakitu/gpu_driver_versions.bin", name: "gpu_driver_versions.bin"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("installerArtifacts() = %v, want %v", got, want)
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
	}

	if got := installerArgs(); !slices.Equal(got, want) {
		t.Errorf("installerArgs() = %v, want %v", got, want)
	}
}
