package launcher

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/oci"
	"github.com/google/go-cmp/cmp"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

// fakeDevStat treats regular files as character devices for unit tests, since tests
// cannot create device nodes without CAP_MKNOD. The inode number stands in for the
// device number, so hard links to the same file simulate nodes with the same major:minor.
func fakeDevStat(path string) (bool, uint64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, 0, err
	}
	if !fi.Mode().IsRegular() {
		return false, 0, nil
	}
	return true, fi.Sys().(*syscall.Stat_t).Ino, nil
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

// writeFakeDevNode creates a regular file (a fake device node) at devDir/name instead of a symlink.
func writeFakeDevNode(t *testing.T, devDir, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(devDir, name), nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

// hardLinkFakeDevNode replaces devDir/newName with a hard link to devDir/oldName, so that
// fakeDevStat reports the same device number for both (like two nodes with the same major:minor).
func hardLinkFakeDevNode(t *testing.T, devDir, oldName, newName string) {
	t.Helper()
	newPath := filepath.Join(devDir, newName)
	if err := os.Remove(newPath); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(devDir, oldName), newPath); err != nil {
		t.Fatal(err)
	}
}

var (
	fakeDTPMLinks = devSymlinks{
		{dev: "tpm0", link: "dtpm"},
		{dev: "tpmrm0", link: "dtpmrm"},
	}
	fakeFTPMLinks = devSymlinks{
		{dev: "tpm1", link: "ftpm"},
		{dev: "tpmrm1", link: "ftpmrm"},
	}
)

// concatLinks returns a new devSymlinks with the given symlinks concatenated.
func concatLinks(links ...devSymlinks) devSymlinks {
	var out devSymlinks
	for _, l := range links {
		out = append(out, l...)
	}
	return out
}

func TestDiscoverFTPMDevs(t *testing.T) {
	tests := []struct {
		name         string
		links        devSymlinks
		containerDir string
		wantDir      string
	}{
		{
			name:         "default_dev_dir",
			links:        concatLinks(fakeDTPMLinks, fakeFTPMLinks),
			containerDir: defaultFTPMContainerDir,
			wantDir:      defaultFTPMContainerDir,
		},
		{
			name:         "relative_container_dir",
			links:        concatLinks(fakeDTPMLinks, fakeFTPMLinks),
			containerDir: "dev/tpm",
			wantDir:      "/dev/tpm",
		},
		{
			name:         "unclean_container_dir",
			links:        concatLinks(fakeDTPMLinks, fakeFTPMLinks),
			containerDir: "/mnt/../dev/",
			wantDir:      "/dev",
		},
		{
			name:         "no_dtpm_symlinks",
			links:        fakeFTPMLinks,
			containerDir: defaultFTPMContainerDir,
			wantDir:      defaultFTPMContainerDir,
		},
		{
			name: "fTPM_at_index_0",
			links: devSymlinks{
				{dev: "tpm1", link: "dtpm"},
				{dev: "tpmrm1", link: "dtpmrm"},
				{dev: "tpm0", link: "ftpm"},
				{dev: "tpmrm0", link: "ftpmrm"},
			},
			containerDir: defaultFTPMContainerDir,
			wantDir:      defaultFTPMContainerDir,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			devDir := newFakeFTPMDevDir(t, tc.links)
			got, err := discoverFTPMDevs(devDir, tc.containerDir, fakeDevStat)
			if err != nil {
				t.Fatalf("discoverFTPMDevs(%q, %q) returned error: %v", devDir, tc.containerDir, err)
			}
			var want []ftpmDevice
			for _, l := range tc.links {
				if l.link == "ftpm" || l.link == "ftpmrm" {
					want = append(want, ftpmDevice{hostPath: filepath.Join(devDir, l.dev), containerPath: filepath.Join(tc.wantDir, l.link)})
				}
			}
			if diff := cmp.Diff(want, got, cmp.AllowUnexported(ftpmDevice{})); diff != "" {
				t.Errorf("discoverFTPMDevs(%q, %q) returned diff (-want +got):\n%s", devDir, tc.containerDir, diff)
			}
		})
	}
}

func TestDiscoverFTPMDevs_NoFTPM(t *testing.T) {
	tests := []struct {
		name    string
		hostDir string
	}{
		{
			// Only Dauntless dTPM symlinks exist (e.g., GCE staging without fTPM firmware).
			name:    "dtpm_only",
			hostDir: newFakeFTPMDevDir(t, fakeDTPMLinks),
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
			got, err := discoverFTPMDevs(tc.hostDir, defaultFTPMContainerDir, fakeDevStat)
			if err != nil {
				t.Fatalf("discoverFTPMDevs(%q, %q) returned error: %v", tc.hostDir, defaultFTPMContainerDir, err)
			}
			if len(got) != 0 {
				t.Errorf("discoverFTPMDevs(%q, %q) = %+v, want no devices", tc.hostDir, defaultFTPMContainerDir, got)
			}
		})
	}
}

func TestDiscoverFTPMDevs_NoContainerDir(t *testing.T) {
	devDir := newFakeFTPMDevDir(t, fakeFTPMLinks)
	if _, err := discoverFTPMDevs(devDir, "", fakeDevStat); err == nil || !strings.Contains(err.Error(), "unspecified") {
		t.Errorf("discoverFTPMDevs(%q, \"\") returned error %v, want error containing %q", devDir, err, "unspecified")
	}
}

func TestDiscoverFTPMDevs_Errors(t *testing.T) {
	tests := []struct {
		name  string
		links devSymlinks
		// setup optionally modifies the fake /dev directory after the symlinks are created.
		setup   func(t *testing.T, devDir string)
		wantErr string
	}{
		// fTPM symlink presence.
		{
			name:    "missing_ftpmrm_partial",
			links:   devSymlinks{{dev: "tpm1", link: "ftpm"}},
			wantErr: "incomplete GB300 fTPM device symlinks",
		},
		{
			name:    "missing_ftpm_partial",
			links:   devSymlinks{{dev: "tpmrm1", link: "ftpmrm"}},
			wantErr: "incomplete GB300 fTPM device symlinks",
		},
		{
			name:    "ftpm_not_symlink",
			links:   devSymlinks{{dev: "tpmrm1", link: "ftpmrm"}},
			setup:   func(t *testing.T, devDir string) { writeFakeDevNode(t, devDir, "ftpm") },
			wantErr: "fTPM path",
		},
		{
			name:    "ftpmrm_not_symlink",
			links:   devSymlinks{{dev: "tpm1", link: "ftpm"}},
			setup:   func(t *testing.T, devDir string) { writeFakeDevNode(t, devDir, "ftpmrm") },
			wantErr: "is not a symlink",
		},
		// fTPM symlink resolution.
		{
			name:    "dangling_ftpm_symlink",
			links:   devSymlinks{{dev: "", link: "ftpm"}, {dev: "tpmrm1", link: "ftpmrm"}},
			wantErr: "failed to resolve fTPM symlink",
		},
		{
			name:    "dangling_ftpmrm_symlink",
			links:   devSymlinks{{dev: "tpm1", link: "ftpm"}, {dev: "", link: "ftpmrm"}},
			wantErr: "failed to resolve fTPM symlink",
		},
		{
			name:    "not_a_char_device",
			links:   devSymlinks{{dev: "tpm1/", link: "ftpm"}, {dev: "tpmrm1", link: "ftpmrm"}},
			wantErr: "not a character device",
		},
		// fTPM tpm<N>/tpmrm<N> pairing.
		{
			name:    "ftpm_not_a_tpm_node",
			links:   devSymlinks{{dev: "nvme0n1", link: "ftpm"}, {dev: "tpmrm1", link: "ftpmrm"}},
			wantErr: "does not match",
		},
		{
			name:    "ftpmrm_resolves_to_raw_tpm_node",
			links:   devSymlinks{{dev: "tpm1", link: "ftpm"}, {dev: "tpm2", link: "ftpmrm"}},
			wantErr: "does not match",
		},
		{
			name:    "swapped_ftpm_ftpmrm",
			links:   devSymlinks{{dev: "tpmrm1", link: "ftpm"}, {dev: "tpm1", link: "ftpmrm"}},
			wantErr: "does not match",
		},
		{
			name:    "mismatched_ftpm_index",
			links:   devSymlinks{{dev: "tpm1", link: "ftpm"}, {dev: "tpmrm2", link: "ftpmrm"}},
			wantErr: "fTPM symlinks resolve to different TPM indexes",
		},
		{
			name:    "same_device_number",
			links:   fakeFTPMLinks,
			setup:   func(t *testing.T, devDir string) { hardLinkFakeDevNode(t, devDir, "tpm1", "tpmrm1") },
			wantErr: "resolve to the same device number",
		},
		// Dauntless dTPM aliasing.
		{
			name: "aliases_dtpm_index",
			links: concatLinks(fakeDTPMLinks, devSymlinks{
				{dev: "tpm0", link: "ftpm"},
				{dev: "tpmrm0", link: "ftpmrm"},
			}),
			wantErr: "Dauntless dTPM device index",
		},
		{
			name:    "aliases_dtpm_device_number",
			links:   concatLinks(fakeDTPMLinks, fakeFTPMLinks),
			setup:   func(t *testing.T, devDir string) { hardLinkFakeDevNode(t, devDir, "tpm0", "tpm1") },
			wantErr: "same device number as Dauntless dTPM device",
		},
		{
			// dtpm exists without dtpmrm, and ftpmrm points at the dTPM's resource manager.
			name: "ftpmrm_aliases_dtpmrm_with_dtpmrm_missing",
			links: devSymlinks{
				{dev: "tpm0", link: "dtpm"},
				{dev: "tpm1", link: "ftpm"},
				{dev: "tpmrm0", link: "ftpmrm"},
			},
			wantErr: "fTPM symlinks resolve to different TPM indexes",
		},
		// dTPM symlink validation.
		{
			name:    "missing_dtpmrm_partial",
			links:   concatLinks(devSymlinks{{dev: "tpm0", link: "dtpm"}}, fakeFTPMLinks),
			wantErr: "incomplete GB300 dTPM device symlinks",
		},
		{
			name:    "dtpm_not_symlink",
			links:   concatLinks(devSymlinks{{dev: "tpmrm0", link: "dtpmrm"}}, fakeFTPMLinks),
			setup:   func(t *testing.T, devDir string) { writeFakeDevNode(t, devDir, "dtpm") },
			wantErr: "dTPM path",
		},
		{
			name:    "dangling_dtpm_symlink",
			links:   concatLinks(devSymlinks{{dev: "", link: "dtpm"}, {dev: "tpmrm0", link: "dtpmrm"}}, fakeFTPMLinks),
			wantErr: "failed to resolve dTPM symlink",
		},
		{
			name:    "mismatched_dtpm_index",
			links:   concatLinks(devSymlinks{{dev: "tpm0", link: "dtpm"}, {dev: "tpmrm2", link: "dtpmrm"}}, fakeFTPMLinks),
			wantErr: "dTPM symlinks resolve to different TPM indexes",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			devDir := newFakeFTPMDevDir(t, tc.links)
			if tc.setup != nil {
				tc.setup(t, devDir)
			}
			_, err := discoverFTPMDevs(devDir, defaultFTPMContainerDir, fakeDevStat)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("discoverFTPMDevs(%q, %q) returned error %v, want error containing %q", devDir, defaultFTPMContainerDir, err, tc.wantErr)
			}
		})
	}
}

func TestCharDevStat(t *testing.T) {
	dir := t.TempDir()
	regularFile := filepath.Join(dir, "regular")
	if err := os.WriteFile(regularFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	nullLink := filepath.Join(dir, "null-link")
	if err := os.Symlink("/dev/null", nullLink); err != nil {
		t.Fatal(err)
	}
	devNull, err := oci.DeviceFromPath("/dev/null")
	if err != nil {
		t.Fatalf("oci.DeviceFromPath(/dev/null) failed: %v", err)
	}
	devZero, err := oci.DeviceFromPath("/dev/zero")
	if err != nil {
		t.Fatalf("oci.DeviceFromPath(/dev/zero) failed: %v", err)
	}

	tests := []struct {
		name      string
		path      string
		wantChar  bool
		wantMajor int64
		wantMinor int64
		wantErr   bool
	}{
		{name: "dev_null", path: "/dev/null", wantChar: true, wantMajor: devNull.Major, wantMinor: devNull.Minor},
		{name: "dev_zero", path: "/dev/zero", wantChar: true, wantMajor: devZero.Major, wantMinor: devZero.Minor},
		{name: "symlink_to_dev_null", path: nullLink, wantChar: true, wantMajor: devNull.Major, wantMinor: devNull.Minor},
		{name: "regular_file", path: regularFile},
		{name: "directory", path: dir},
		{name: "not_existing", path: filepath.Join(dir, "missing"), wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotChar, gotRdev, err := charDevStat(tc.path)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("charDevStat(%q) returned error (%v), want error (%v)", tc.path, err, tc.wantErr)
			}
			if gotChar != tc.wantChar {
				t.Errorf("charDevStat(%q) isChar = %v, want %v", tc.path, gotChar, tc.wantChar)
			}
			if !tc.wantChar {
				return
			}
			if major, minor := int64(unix.Major(gotRdev)), int64(unix.Minor(gotRdev)); major != tc.wantMajor || minor != tc.wantMinor {
				t.Errorf("charDevStat(%q) rdev = %d:%d, want %d:%d", tc.path, major, minor, tc.wantMajor, tc.wantMinor)
			}
		})
	}
}

func TestWithFTPMDevice_SetsMode0666AndCgroupRW(t *testing.T) {
	// Use a host character device whose mode is not already 0666, so that the test
	// verifies that withFTPMDevice overrides the host FileMode inside the container.
	var hostCharDev string
	for _, p := range []string{"/dev/console", "/dev/kmsg", "/dev/mem", "/dev/tty0"} {
		if d, err := oci.DeviceFromPath(p); err == nil && d.Type == "c" && *d.FileMode != ftpmContainerFileMode {
			hostCharDev = p
			break
		}
	}
	if hostCharDev == "" {
		t.Skip("no host character device with a non-0666 mode found")
	}

	// Seed a pre-existing device (e.g. a Local SSD block device) with a non-0666 mode to verify
	// that withFTPMDevice only overrides the mode of the devices that it adds.
	lssdMode := os.FileMode(0o660)
	lssd := specs.LinuxDevice{Path: "/dev/disk/by-id/google-local-nvme-ssd-0", Type: "b", Major: 259, Minor: 0, FileMode: &lssdMode}
	gotSpec := oci.Spec{Linux: &specs.Linux{Devices: []specs.LinuxDevice{lssd}}}

	if err := withFTPMDevice(hostCharDev, "/dev/ftpmrm")(context.Background(), nil, &containers.Container{ID: "test"}, &gotSpec); err != nil {
		t.Fatalf("withFTPMDevice(%q) failed: %v", hostCharDev, err)
	}

	if len(gotSpec.Linux.Devices) != 2 {
		t.Fatalf("got devices = %+v, want 2 LinuxDevices", gotSpec.Linux.Devices)
	}
	if diff := cmp.Diff(lssd, gotSpec.Linux.Devices[0]); diff != "" {
		t.Errorf("pre-existing device changed (-want +got):\n%s", diff)
	}
	if lssdMode != 0o660 {
		t.Errorf("pre-existing device FileMode changed to %#o, want 0660", lssdMode)
	}
	dev := gotSpec.Linux.Devices[1]
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
