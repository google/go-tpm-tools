package gpu

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const (
	artifactsHostDir    = "/var/lib/nvidia-artifacts"
	artifactsBaseURL    = "https://storage.googleapis.com"
	osReleasePath       = "/etc/os-release"
	prebuiltModulesFile = "nvidia-drivers-" + NvDriverVer595_58_03 + ".tgz"
	driverVersionsFile  = "gpu_driver_versions.bin"
)

// artifact defines a file to stage; an empty digest skips verification.
type artifact struct {
	url    string
	name   string
	digest string
}

// installerArtifacts leaves the driver versions file unchecked because an unexpected GPU version mapping causes the installer to request unstaged files and fail.
func installerArtifacts(baseURL, buildID, prebuiltModulesDigest string) []artifact {
	cosTools := fmt.Sprintf("%s/cos-tools/%s/lakitu", baseURL, buildID)
	return []artifact{
		{url: fmt.Sprintf("%s/cos-nvidia-gpu-drivers/%s", baseURL, NvDriverVer595_58_03Runfile), name: NvDriverVer595_58_03Runfile, digest: NvDriverVer595_58_03Digest},
		{url: fmt.Sprintf("%s/%s", cosTools, prebuiltModulesFile), name: prebuiltModulesFile, digest: prebuiltModulesDigest},
		{url: fmt.Sprintf("%s/%s", cosTools, driverVersionsFile), name: driverVersionsFile},
	}
}

func installerArgs() []string {
	return []string{
		"/cos-gpu-installer",
		"install",
		fmt.Sprintf("-version=%s", NvDriverVer595_58_03),
		fmt.Sprintf("-host-dir=%s", InstallationHostDir),
		"--no-verify",
		fmt.Sprintf("-local-artifacts-dir=%s", path.Join("/root", artifactsHostDir)),
	}
}

func readBuildID(osRelease string) (string, error) {
	data, err := os.ReadFile(osRelease)
	if err != nil {
		return "", fmt.Errorf("failed to read %s: %w", osRelease, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if id, ok := strings.CutPrefix(line, "BUILD_ID="); ok {
			return strings.Trim(id, `"`), nil
		}
	}
	return "", fmt.Errorf("BUILD_ID not found in %s", osRelease)
}

func stageArtifacts(ctx context.Context, client *http.Client, dir string, artifacts []artifact) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", dir, err)
	}
	for _, a := range artifacts {
		if err := downloadArtifact(ctx, client, dir, a); err != nil {
			return err
		}
	}
	return nil
}

func downloadArtifact(ctx context.Context, client *http.Client, dir string, a artifact) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request for %s: %w", a.url, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download %s: %w", a.url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download %s: status %s", a.url, resp.Status)
	}

	dst := filepath.Join(dir, a.name)
	f, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", dst, err)
	}
	h := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(f, h), resp.Body)
	closeErr := f.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return fmt.Errorf("failed to write %s: %w", dst, err)
	}

	if a.digest == "" {
		return nil
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != a.digest {
		return fmt.Errorf("%s digest mismatch: got %s, want %s", a.name, got, a.digest)
	}
	return nil
}
