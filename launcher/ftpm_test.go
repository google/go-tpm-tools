package launcher

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/oci"
	"github.com/google/go-cmp/cmp"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// fakeCharDevChecker treats regular files as character devices for unit tests,
// since tests cannot create arbitrary device nodes without CAP_MKNOD.
func fakeCharDevChecker(path string) (bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return fi.Mode().IsRegular(), nil
}

// newFakeFTPMDevDir creates fake device files and symlinks in a temporary /dev directory.
// An empty dev target creates a dangling symlink; a target ending in "/" creates a subdirectory.
func newFakeFTPMDevDir(t *testing.T, links devSymlinks) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	devDir := filepath.Join(root, "dev")
	if err := os.MkdirAll(devDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, link := range links {
		target := link.dev
		switch {
		case target == "":
			target = "dangling"
		case strings.HasSuffix(target, "/"):
			if err := os.MkdirAll(filepath.Join(devDir, strings.TrimSuffix(target, "/")), 0o755); err != nil {
				t.Fatal(err)
			}
		default:
			devPath := filepath.Join(devDir, target)
			if _, err := os.Stat(devPath); err != nil {
				if err := os.WriteFile(devPath, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
		if err := os.Symlink(strings.TrimSuffix(target, "/"), filepath.Join(devDir, link.link)); err != nil {
			t.Fatal(err)
		}
	}
	return devDir
}

func TestDiscoverFTPMDevs(t *testing.T) {
	devDir := newFakeFTPMDevDir(t, devSymlinks{
		{dev: "tpm0", link: "dtpm"},
		{dev: "tpmrm0", link: "dtpmrm"},
		{dev: "tpm1", link: "ftpm"},
		{dev: "tpmrm1", link: "ftpmrm"},
	})

	tests := []struct {
		name         string
		containerDir string
		wantDir      string
	}{
		{
			name:         "default_dev_dir",
			containerDir: defaultFTPMContainerDir,
			wantDir:      defaultFTPMContainerDir,
		},
		{
			name:         "relative_container_dir",
			containerDir: "dev/tpm",
			wantDir:      "/dev/tpm",
		},
		{
			name:         "unclean_container_dir",
			containerDir: "/mnt/../dev/",
			wantDir:      "/dev",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := discoverFTPMDevs(devDir, tc.containerDir, fakeCharDevChecker)
			if err != nil {
				t.Fatalf("discoverFTPMDevs(%q, %q) returned error: %v", devDir, tc.containerDir, err)
			}
			want := []ftpmDevice{
				{hostPath: filepath.Join(devDir, "tpm1"), containerPath: filepath.Join(tc.wantDir, "ftpm")},
				{hostPath: filepath.Join(devDir, "tpmrm1"), containerPath: filepath.Join(tc.wantDir, "ftpmrm")},
			}
			if diff := cmp.Diff(want, got, cmp.AllowUnexported(ftpmDevice{})); diff != "" {
				t.Errorf("discoverFTPMDevs(%q, %q) returned diff (-want +got):\n%s", devDir, tc.containerDir, diff)
			}
		})
	}
}

func TestDiscoverFTPMDevs_NoFTPM(t *testing.T) {
	// Only Dauntless dTPM symlinks exist (e.g., GCE staging without fTPM firmware).
	dtpmOnlyDir := newFakeFTPMDevDir(t, devSymlinks{
		{dev: "tpm0", link: "dtpm"},
		{dev: "tpmrm0", link: "dtpmrm"},
	})

	tests := []struct {
		name    string
		hostDir string
	}{
		{
			name:    "dtpm_only",
			hostDir: dtpmOnlyDir,
		},
		{
			name:    "empty_dir",
			hostDir: newFakeFTPMDevDir(t, nil),
		},
		{
			name:    "missing_dir",
			hostDir: filepath.Join(t.TempDir(), "does-not-exist"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := discoverFTPMDevs(tc.hostDir, defaultFTPMContainerDir, fakeCharDevChecker)
			if err != nil {
				t.Fatalf("discoverFTPMDevs(%q, %q) returned error: %v", tc.hostDir, defaultFTPMContainerDir, err)
			}
			if len(got) != 0 {
				t.Errorf("discoverFTPMDevs(%q, %q) = %+v, want no devices", tc.hostDir, defaultFTPMContainerDir, got)
			}
		})
	}
}

func TestDiscoverFTPMDevs_Errors(t *testing.T) {
	tests := []struct {
		name         string
		links        devSymlinks
		containerDir string
		wantErr      string
	}{
		{
			name: "no_container_dir",
			links: devSymlinks{
				{dev: "tpm1", link: "ftpm"},
				{dev: "tpmrm1", link: "ftpmrm"},
			},
			containerDir: "",
			wantErr:      "unspecified",
		},
		{
			name: "missing_ftpmrm_partial",
			links: devSymlinks{
				{dev: "tpm1", link: "ftpm"},
			},
			containerDir: defaultFTPMContainerDir,
			wantErr:      "incomplete GB300 fTPM device symlinks",
		},
		{
			name: "missing_ftpm_partial",
			links: devSymlinks{
				{dev: "tpmrm1", link: "ftpmrm"},
			},
			containerDir: defaultFTPMContainerDir,
			wantErr:      "incomplete GB300 fTPM device symlinks",
		},
		{
			name: "dangling_ftpm_symlink",
			links: devSymlinks{
				{dev: "", link: "ftpm"},
				{dev: "tpmrm1", link: "ftpmrm"},
			},
			containerDir: defaultFTPMContainerDir,
			wantErr:      "failed to resolve fTPM symlink",
		},
		{
			name: "dangling_ftpmrm_symlink",
			links: devSymlinks{
				{dev: "tpm1", link: "ftpm"},
				{dev: "", link: "ftpmrm"},
			},
			containerDir: defaultFTPMContainerDir,
			wantErr:      "failed to resolve fTPM symlink",
		},
		{
			name: "not_a_char_device",
			links: devSymlinks{
				{dev: "subdir/", link: "ftpm"},
				{dev: "tpmrm1", link: "ftpmrm"},
			},
			containerDir: defaultFTPMContainerDir,
			wantErr:      "not a character device",
		},
		{
			name: "same_device_twice",
			links: devSymlinks{
				{dev: "tpm1", link: "ftpm"},
				{dev: "tpm1", link: "ftpmrm"},
			},
			containerDir: defaultFTPMContainerDir,
			wantErr:      "same device",
		},
		{
			name: "aliases_dauntless_dtpm",
			links: devSymlinks{
				{dev: "tpm0", link: "dtpm"},
				{dev: "tpmrm0", link: "dtpmrm"},
				{dev: "tpm0", link: "ftpm"},
				{dev: "tpmrm1", link: "ftpmrm"},
			},
			containerDir: defaultFTPMContainerDir,
			wantErr:      "Dauntless dTPM device",
		},
		{
			name: "dangling_dtpm_symlink",
			links: devSymlinks{
				{dev: "", link: "dtpm"},
				{dev: "tpm1", link: "ftpm"},
				{dev: "tpmrm1", link: "ftpmrm"},
			},
			containerDir: defaultFTPMContainerDir,
			wantErr:      "failed to resolve dTPM symlink",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			devDir := newFakeFTPMDevDir(t, tc.links)
			_, err := discoverFTPMDevs(devDir, tc.containerDir, fakeCharDevChecker)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("discoverFTPMDevs(%q, %q) returned error %v, want error containing %q", devDir, tc.containerDir, err, tc.wantErr)
			}
		})
	}
}

func TestIsCharDevice(t *testing.T) {
	regularFile := filepath.Join(t.TempDir(), "regular")
	if err := os.WriteFile(regularFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		path    string
		want    bool
		wantErr bool
	}{
		{
			name:    "char_dev_null",
			path:    "/dev/null",
			want:    true,
			wantErr: false,
		},
		{
			name:    "regular_file",
			path:    regularFile,
			want:    false,
			wantErr: false,
		},
		{
			name:    "directory",
			path:    t.TempDir(),
			want:    false,
			wantErr: false,
		},
		{
			name:    "not_existing",
			path:    filepath.Join(t.TempDir(), "missing"),
			want:    false,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := isCharDevice(tc.path)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("isCharDevice(%q) returned error (%v), want error (%v)", tc.path, err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("isCharDevice(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestWithFTPMDevice_SetsMode0666AndCgroupRW(t *testing.T) {
	// Prefer /dev/console (typically 0600 or 0620 on Linux) when present so we verify
	// that a restrictive host FileMode is overridden to 0666 inside the container.
	hostCharDev := "/dev/null"
	if ok, err := isCharDevice("/dev/console"); err == nil && ok {
		hostCharDev = "/dev/console"
	}

	var gotSpec oci.Spec
	if err := withFTPMDevice(hostCharDev, "/dev/ftpmrm")(context.Background(), nil, &containers.Container{ID: "test"}, &gotSpec); err != nil {
		t.Fatalf("withFTPMDevice(%q) failed: %v", hostCharDev, err)
	}

	if gotSpec.Linux == nil || len(gotSpec.Linux.Devices) != 1 {
		t.Fatalf("got devices = %+v, want 1 LinuxDevice", gotSpec.Linux)
	}
	dev := gotSpec.Linux.Devices[0]
	if dev.Path != "/dev/ftpmrm" || dev.Type != "c" {
		t.Errorf("got device = %+v, want Path=/dev/ftpmrm Type=c", dev)
	}
	if dev.FileMode == nil || *dev.FileMode != ftpmContainerFileMode {
		t.Errorf("got FileMode = %v, want %#o", dev.FileMode, ftpmContainerFileMode)
	}

	if gotSpec.Linux.Resources == nil || len(gotSpec.Linux.Resources.Devices) != 1 {
		t.Fatalf("got cgroup devices = %+v, want 1 LinuxDeviceCgroup", gotSpec.Linux.Resources)
	}
	cg := gotSpec.Linux.Resources.Devices[0]
	wantCG := specs.LinuxDeviceCgroup{
		Allow:  true,
		Type:   "c",
		Major:  &dev.Major,
		Minor:  &dev.Minor,
		Access: "rw",
	}
	if diff := cmp.Diff(wantCG, cg); diff != "" {
		t.Errorf("LinuxDeviceCgroup mismatch (-want +got):\n%s", diff)
	}
}
