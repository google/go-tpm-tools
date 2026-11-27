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
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/go-tpm-tools/launcher/internal/logging"
)

const (
	artifactsHostDir       = "/var/lib/nvidia-artifacts"
	artifactsBaseURL       = "https://storage.googleapis.com"
	osReleasePath          = "/etc/os-release"
	prebuiltModulesFile    = "nvidia-drivers-" + NvDriverVer595_58_03 + ".tgz"
	driverVersionsFile     = "gpu_driver_versions.bin"
	downloadAttemptTimeout = 5 * time.Minute
	downloadMaxRetries     = 3
)

func installerArgs() []string {
	return []string{
		"/cos-gpu-installer",
		"install",
		fmt.Sprintf("-version=%s", NvDriverVer595_58_03),
		fmt.Sprintf("-host-dir=%s", InstallationHostDir),
		"--no-verify",
		fmt.Sprintf("-local-artifacts-dir=%s", path.Join("/root", artifactsHostDir)),
		"-use-regional-bucket=false",
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

func downloadBackoffPolicy() backoff.BackOff {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = time.Second
	return backoff.WithMaxRetries(b, downloadMaxRetries)
}

func isRetryableStatus(code int) bool {
	return code == http.StatusRequestTimeout || code == http.StatusTooManyRequests || code >= http.StatusInternalServerError
}

func retryDownload(ctx context.Context, logger logging.Logger, name string, attemptTimeout time.Duration, newBackoff func() backoff.BackOff, fn func(context.Context) error) error {
	logger.Info(fmt.Sprintf("Downloading GPU driver artifact %s", name))
	op := func() error {
		attemptCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
		defer cancel()
		return fn(attemptCtx)
	}
	notify := func(err error, d time.Duration) {
		logger.Warn(fmt.Sprintf("Retrying GPU driver artifact %s after %s: %v", name, d, err))
	}
	return backoff.RetryNotify(op, backoff.WithContext(newBackoff(), ctx), notify)
}

func stageArtifacts(ctx context.Context, client *http.Client, logger logging.Logger, dir, baseURL, buildID, runfileDigest, prebuiltModulesDigest string, attemptTimeout time.Duration, newBackoff func() backoff.BackOff) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", dir, err)
	}
	cosTools := fmt.Sprintf("%s/cos-tools/%s/lakitu", baseURL, buildID)
	if err := retryDownload(ctx, logger, NvDriverVer595_58_03Runfile, attemptTimeout, newBackoff, func(ctx context.Context) error {
		return downloadVerify(ctx, client, fmt.Sprintf("%s/cos-nvidia-gpu-drivers/%s", baseURL, NvDriverVer595_58_03Runfile), filepath.Join(dir, NvDriverVer595_58_03Runfile), runfileDigest)
	}); err != nil {
		return err
	}
	if err := retryDownload(ctx, logger, prebuiltModulesFile, attemptTimeout, newBackoff, func(ctx context.Context) error {
		return downloadVerify(ctx, client, fmt.Sprintf("%s/%s", cosTools, prebuiltModulesFile), filepath.Join(dir, prebuiltModulesFile), prebuiltModulesDigest)
	}); err != nil {
		return err
	}
	// gpu_driver_versions.bin is unchecked because an unexpected GPU version mapping causes the installer to request unstaged files and fail.
	return retryDownload(ctx, logger, driverVersionsFile, attemptTimeout, newBackoff, func(ctx context.Context) error {
		_, err := download(ctx, client, fmt.Sprintf("%s/%s", cosTools, driverVersionsFile), filepath.Join(dir, driverVersionsFile))
		return err
	})
}

func download(ctx context.Context, client *http.Client, url, dst string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", backoff.Permanent(fmt.Errorf("failed to create request for %s: %w", url, err))
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("failed to download %s: status %s", url, resp.Status)
		if !isRetryableStatus(resp.StatusCode) {
			return "", backoff.Permanent(err)
		}
		return "", err
	}

	f, err := os.Create(dst)
	if err != nil {
		return "", fmt.Errorf("failed to create %s: %w", dst, err)
	}
	h := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(f, h), resp.Body)
	closeErr := f.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return "", fmt.Errorf("failed to write %s: %w", dst, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func downloadVerify(ctx context.Context, client *http.Client, url, dst, wantDigest string) error {
	if wantDigest == "" {
		return backoff.Permanent(fmt.Errorf("%s digest is required", filepath.Base(dst)))
	}
	got, err := download(ctx, client, url, dst)
	if err != nil {
		return err
	}
	if got != wantDigest {
		return backoff.Permanent(fmt.Errorf("%s digest mismatch: got %s, want %s", filepath.Base(dst), got, wantDigest))
	}
	return nil
}
