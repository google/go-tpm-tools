package launchermount

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/opencontainers/runtime-spec/specs-go"
)

var _ Mount = LSSDMount{}

// stubBlockDevices makes isBlockDevice treat regular files as block devices,
// since tests cannot create device nodes without CAP_MKNOD.
func stubBlockDevices(t *testing.T) {
	t.Helper()
	orig := isBlockDevice
	isBlockDevice = func(path string) (bool, error) {
		fi, err := os.Stat(path)
		if err != nil {
			return false, err
		}
		return fi.Mode().IsRegular(), nil
	}
	t.Cleanup(func() { isBlockDevice = orig })
}

type devSymlinks []struct{ dev, link string }

// newFakeByID creates a fake device file under /dev and a /dev/disk/by-id containing the given symlinks.
// This resembles the real /dev and /dev/disk/by-id.
func newFakeByID(t *testing.T, links devSymlinks) (dev, byID string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dev = filepath.Join(root, "dev")
	byID = filepath.Join(dev, "disk", "by-id")
	if err := os.MkdirAll(byID, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, link := range links {
		if link.dev != "" {
			devPath := filepath.Join(dev, link.dev)
			if _, err := os.Stat(devPath); err != nil { // Create a new file only if the file does not exist for testing.
				if err := os.WriteFile(devPath, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		} else {
			link.dev = "dangling"
		}
		if err := os.Symlink(filepath.Join("..", "..", link.dev), filepath.Join(byID, link.link)); err != nil {
			t.Fatal(err)
		}
	}
	return dev, byID
}

func TestCreateLSSDMounts(t *testing.T) {
	stubBlockDevices(t)
	// The GB300 bare metal layout, plus ssd-10 to check that mounts are sorted
	// by index rather than lexically. Partitions and other by-id symlinks to
	// the same devices must be skipped.
	dev, byID := newFakeByID(t,
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
		name              string
		containerDestPath string
		wantDestDir       string
	}{
		{"Absolute Dest", "/dev/disk/by-id", "/dev/disk/by-id"},
		{"Relative Dest", "mnt/lssd", "/mnt/lssd"},
		{"Unclean Dest", "/mnt/../lssd/", "/lssd"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CreateLSSDMounts(byID, tc.containerDestPath)
			if err != nil {
				t.Fatalf("CreateLSSDMounts(%q, %q) returned error: %v", byID, tc.containerDestPath, err)
			}
			slices.SortFunc(got, func(a, b LSSDMount) int {
				return strings.Compare(a.source, b.source)
			})
			want := []LSSDMount{
				{source: filepath.Join(dev, "nvme0n1"), destination: filepath.Join(tc.wantDestDir, "google-local-nvme-ssd-1")},
				{source: filepath.Join(dev, "nvme10n1"), destination: filepath.Join(tc.wantDestDir, "google-local-nvme-ssd-10")},
				{source: filepath.Join(dev, "nvme1n1"), destination: filepath.Join(tc.wantDestDir, "google-local-nvme-ssd-2")},
				{source: filepath.Join(dev, "nvme2n1"), destination: filepath.Join(tc.wantDestDir, "google-local-nvme-ssd-0")},
				{source: filepath.Join(dev, "nvme4n1"), destination: filepath.Join(tc.wantDestDir, "google-local-nvme-ssd-3")},
			}
			if diff := cmp.Diff(want, got, cmp.AllowUnexported(LSSDMount{})); diff != "" {
				t.Errorf("CreateLSSDMounts(%q, %q) returned diff (-want +got):\n%s", byID, tc.containerDestPath, diff)
			}
		})
	}
}

func TestCreateLSSDMountsNoLSSDs(t *testing.T) {
	stubBlockDevices(t)
	_, emptyByID := newFakeByID(t, nil)

	tests := []struct {
		name     string
		hostPath string
	}{
		{"Empty Dir", emptyByID},
		{"Missing Dir", filepath.Join(t.TempDir(), "does-not-exist")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CreateLSSDMounts(tc.hostPath, "/dev/disk/by-id")
			if err != nil {
				t.Fatalf("CreateLSSDMounts(%q) returned error: %v", tc.hostPath, err)
			}
			if len(got) != 0 {
				t.Errorf("CreateLSSDMounts(%q) = %+v, want no mounts", tc.hostPath, got)
			}
		})
	}
}

func TestCreateLSSDMountsFail(t *testing.T) {
	stubBlockDevices(t)
	tests := []struct {
		name              string
		links             devSymlinks
		containerDestPath string
		wantErr           string
	}{
		{
			name:              "no dest",
			links:             devSymlinks{{dev: "nvme0n1", link: "google-local-nvme-ssd-0"}},
			containerDestPath: "",
			wantErr:           "destination unspecified",
		},
		{
			name:              "dangling symlink",
			links:             devSymlinks{{dev: "", link: "google-local-nvme-ssd-0"}},
			containerDestPath: "/dev/disk/by-id",
			wantErr:           "failed to resolve",
		},
		{
			name:              "not a block device",
			links:             devSymlinks{{dev: "disk", link: "google-local-nvme-ssd-0"}},
			containerDestPath: "/dev/disk/by-id",
			wantErr:           "is not a block device",
		},
		{
			name: "same device twice",
			links: devSymlinks{
				{dev: "nvme0n1", link: "google-local-nvme-ssd-0"},
				{dev: "nvme0n1", link: "google-local-nvme-ssd-1"},
			},
			containerDestPath: "/dev/disk/by-id",
			wantErr:           "resolve to the same device",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, byID := newFakeByID(t, tc.links)
			_, err := CreateLSSDMounts(byID, tc.containerDestPath)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("CreateLSSDMounts(%q, %q) returned error %v, want error containing %q", byID, tc.containerDestPath, err, tc.wantErr)
			}
		})
	}
}

func TestIsBlockDevice(t *testing.T) {
	regularFile := filepath.Join(t.TempDir(), "regular")
	if err := os.WriteFile(regularFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// Character devices (e.g. /dev/null, /dev/nvidia0) are not block devices.
	for _, path := range []string{regularFile, "/dev/null"} {
		got, err := isBlockDevice(path)
		if err != nil {
			t.Fatalf("isBlockDevice(%q) returned error: %v", path, err)
		}
		if got {
			t.Errorf("isBlockDevice(%q) = true, want false", path)
		}
	}
	if _, err := isBlockDevice(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("isBlockDevice(missing) returned nil error, want non-nil")
	}
}

func TestLSSDMountSpecsMount(t *testing.T) {
	mnt := LSSDMount{source: "/dev/nvme2n1", destination: "/dev/disk/by-id/google-local-nvme-ssd-0"}
	want := specs.Mount{
		Type:        "bind",
		Source:      "/dev/nvme2n1",
		Destination: "/dev/disk/by-id/google-local-nvme-ssd-0",
		Options:     []string{"bind", "rw"},
	}
	if diff := cmp.Diff(want, mnt.SpecsMount()); diff != "" {
		t.Errorf("SpecsMount() returned diff (-want +got):\n%s", diff)
	}
	if got := mnt.Mountpoint(); got != want.Destination {
		t.Errorf("Mountpoint() = %q, want %q", got, want.Destination)
	}
}
