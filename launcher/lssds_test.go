package launcher

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// fakeBlockDevChecker treats regular files as block devices for testing,
// since tests cannot create device nodes without CAP_MKNOD.
func fakeBlockDevChecker(path string) (bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return fi.Mode().IsRegular(), nil
}

type devSymlinks []struct {
	dev, link string
}

// newFakeByID creates fake device files under /dev/ and symlinks under /dev/disk/by-id/, returning both directory paths.
// This resembles the real /dev/ and /dev/disk/by-id/.
func newFakeByID(t *testing.T, links devSymlinks) (string, string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	devDir := filepath.Join(root, "dev")
	byIDDir := filepath.Join(devDir, "disk", "by-id")
	if err := os.MkdirAll(byIDDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, link := range links {
		if link.dev != "" {
			devPath := filepath.Join(devDir, link.dev)
			// Create the fake device file only if an earlier symlink has not created it yet.
			if _, err := os.Stat(devPath); err != nil {
				if err := os.WriteFile(devPath, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		} else { // An empty dev creates a dangling symlink.
			link.dev = "dangling"
		}
		if err := os.Symlink(filepath.Join("..", "..", link.dev), filepath.Join(byIDDir, link.link)); err != nil {
			t.Fatal(err)
		}
	}
	return devDir, byIDDir
}

func TestDiscoverLSSDDevs(t *testing.T) {
	// The GB300 layout, plus ssd-10 to cover multi-digit indexes.
	// Partition links and other by-id aliases of the same device must be skipped.
	devDir, byIDDir := newFakeByID(t,
		devSymlinks{
			{dev: "nvme2n1", link: "google-local-nvme-ssd-0"},
			{dev: "nvme2n1p1", link: "google-local-nvme-ssd-0-part1"},
			{dev: "nvme0n1", link: "google-local-nvme-ssd-1"},
			{dev: "nvme1n1", link: "google-local-nvme-ssd-2"},
			{dev: "nvme4n1", link: "google-local-nvme-ssd-3"},
			{dev: "nvme10n1", link: "google-local-nvme-ssd-10"},
			{dev: "nvme2n1", link: "nvme-nvme_card_SN0"},
		})

	tests := []struct {
		name         string
		containerDir string
		wantDir      string
	}{
		{
			name:         "absolute_container_dir",
			containerDir: defaultLSSDContainerDir,
			wantDir:      defaultLSSDContainerDir,
		},
		{
			name:         "relative_container_dir",
			containerDir: "mnt/lssd",
			wantDir:      "/mnt/lssd",
		},
		{
			name:         "unclean_container_dir",
			containerDir: "/mnt/../lssd/",
			wantDir:      "/lssd",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := discoverLSSDDevs(byIDDir, tc.containerDir, fakeBlockDevChecker)
			if err != nil {
				t.Fatalf("discoverLSSDDevs(%q, %q) returned error: %v", byIDDir, tc.containerDir, err)
			}
			want := []lssdDevice{
				{hostPath: filepath.Join(devDir, "nvme2n1"), containerPath: filepath.Join(tc.wantDir, "google-local-nvme-ssd-0")},
				{hostPath: filepath.Join(devDir, "nvme0n1"), containerPath: filepath.Join(tc.wantDir, "google-local-nvme-ssd-1")},
				{hostPath: filepath.Join(devDir, "nvme10n1"), containerPath: filepath.Join(tc.wantDir, "google-local-nvme-ssd-10")},
				{hostPath: filepath.Join(devDir, "nvme1n1"), containerPath: filepath.Join(tc.wantDir, "google-local-nvme-ssd-2")},
				{hostPath: filepath.Join(devDir, "nvme4n1"), containerPath: filepath.Join(tc.wantDir, "google-local-nvme-ssd-3")},
			}
			if diff := cmp.Diff(want, got, cmp.AllowUnexported(lssdDevice{})); diff != "" {
				t.Errorf("discoverLSSDDevs(%q, %q) returned diff (-want +got):\n%s", byIDDir, tc.containerDir, diff)
			}
		})
	}
}

func TestDiscoverLSSDDevs_NoLSSDs(t *testing.T) {
	_, byIDDir := newFakeByID(t, nil)

	tests := []struct {
		name    string
		hostDir string
	}{
		{
			name:    "empty_dir",
			hostDir: byIDDir,
		},
		{
			name:    "missing_dir",
			hostDir: filepath.Join(t.TempDir(), "does-not-exist"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := discoverLSSDDevs(tc.hostDir, defaultLSSDContainerDir, fakeBlockDevChecker)
			if err != nil {
				t.Fatalf("discoverLSSDDevs(%q, %q) returned error: %v", tc.hostDir, defaultLSSDContainerDir, err)
			}
			if len(got) != 0 {
				t.Errorf("discoverLSSDDevs(%q, %q) = %+v, want no devices", tc.hostDir, defaultLSSDContainerDir, got)
			}
		})
	}
}

func TestDiscoverLSSDDevs_Errors(t *testing.T) {
	tests := []struct {
		name         string
		links        devSymlinks
		containerDir string
		wantErr      string
	}{
		{
			name:         "no_container_dir",
			links:        devSymlinks{{dev: "nvme0n1", link: "google-local-nvme-ssd-0"}},
			containerDir: "",
			wantErr:      "unspecified",
		},
		{
			name:         "dangling_symlink",
			links:        devSymlinks{{dev: "", link: "google-local-nvme-ssd-0"}},
			containerDir: defaultLSSDContainerDir,
			wantErr:      "failed to resolve",
		},
		{
			name: "not_a_block_device",
			// "disk" is the "/dev/disk" directory, i.e. not a regular file.
			links:        devSymlinks{{dev: "disk", link: "google-local-nvme-ssd-0"}},
			containerDir: defaultLSSDContainerDir,
			wantErr:      "not a block device",
		},
		{
			name: "same_device_twice",
			links: devSymlinks{
				{dev: "nvme0n1", link: "google-local-nvme-ssd-0"},
				{dev: "nvme0n1", link: "google-local-nvme-ssd-1"},
			},
			containerDir: defaultLSSDContainerDir,
			wantErr:      "same device",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, byID := newFakeByID(t, tc.links)
			_, err := discoverLSSDDevs(byID, tc.containerDir, fakeBlockDevChecker)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("discoverLSSDDevs(%q, %q) returned error %v, want error containing %q", byID, tc.containerDir, err, tc.wantErr)
			}
		})
	}
}

func TestIsBlockDevice(t *testing.T) {
	regularFile := filepath.Join(t.TempDir(), "regular")
	if err := os.WriteFile(regularFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "regular_file",
			path:    regularFile,
			wantErr: false,
		},
		{
			name:    "char_dev",
			path:    "/dev/null",
			wantErr: false,
		},
		{
			name:    "not_existing",
			path:    filepath.Join(t.TempDir(), "missing"),
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Only negative cases: creating a block device node requires CAP_MKNOD.
			got, err := isBlockDevice(tc.path)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("isBlockDevice(%q) returned error (%v), want error (%v)", tc.path, err, tc.wantErr)
			}
			if got {
				t.Errorf("isBlockDevice(%q) = true, want false", tc.path)
			}
		})
	}
}
