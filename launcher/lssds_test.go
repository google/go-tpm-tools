package launcher

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-tpm-tools/launcher/internal/logging"
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

type fakeMDS struct {
	data string
	err  error
}

func (f fakeMDS) GetWithContext(_ context.Context, suffix string) (string, error) {
	if suffix != instanceDisksQuery {
		return "", fmt.Errorf("unexpected metadata query %q, want %q", suffix, instanceDisksQuery)
	}
	return f.data, f.err
}

func TestAttachedLSSDCount(t *testing.T) {
	tests := []struct {
		name    string
		mds     fakeMDS
		want    int
		wantErr string
	}{
		{
			name: "gb300_disks",
			// The data below resembles a real-world example.
			mds: fakeMDS{data: `[
				{"deviceName":"persistent-disk-0","index":0,"interface":"NVME","mode":"READ_WRITE","nvmeNamespaceIdentifier":3557249916533568973,"type":"HYPERDISK-BALANCED"},
				{"deviceName":"local-ssd-0","index":1,"interface":"NVME","mode":"READ_WRITE","type":"LOCAL-SSD"},
				{"deviceName":"local-ssd-1","index":2,"interface":"NVME","mode":"READ_WRITE","type":"LOCAL-SSD"},
				{"deviceName":"local-ssd-2","index":3,"interface":"NVME","mode":"READ_WRITE","type":"LOCAL-SSD"},
				{"deviceName":"local-ssd-3","index":4,"interface":"NVME","mode":"READ_WRITE","type":"LOCAL-SSD"}
			]`},
			want: 4,
		},
		{
			name: "only_boot_disk",
			mds:  fakeMDS{data: `[{"deviceName":"persistent-disk-0","interface":"NVME","type":"HYPERDISK-BALANCED"}]`},
			want: 0,
		},
		{
			name: "empty_list",
			mds:  fakeMDS{data: `[]`},
			want: 0,
		},
		{
			name:    "mds_error",
			mds:     fakeMDS{err: errors.New("mds unreachable")},
			wantErr: "mds unreachable",
		},
		{
			name:    "invalid_json",
			mds:     fakeMDS{data: "not-json"},
			wantErr: "failed to parse",
		},
		{
			name:    "non_nvme_interface",
			mds:     fakeMDS{data: `[{"deviceName":"local-ssd-0","interface":"SCSI","type":"LOCAL-SSD"}]`},
			wantErr: "unsupported Local SSD interface",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := attachedLSSDCount(t.Context(), tc.mds)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("attachedLSSDCount() error = %v, want error containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("attachedLSSDCount() returned unexpected error: %v", err)
			} else if got != tc.want {
				t.Errorf("attachedLSSDCount() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestPresentLSSDCount(t *testing.T) {
	_, byIDDir := newFakeByID(t, devSymlinks{
		{dev: "nvme0n1", link: "google-local-nvme-ssd-2"},   // Valid
		{dev: "nvme0n1", link: "google-local-nvme-ssd-0"},   // Valid (duplicate device name)
		{dev: "nvme10n1", link: "google-local-nvme-ssd-10"}, // Valid
		{dev: "", link: "google-local-nvme-ssd-3"},          // Valid (dangling symlink)
		{dev: "nvme0n1p1", link: "google-local-nvme-ssd-0-part1"},
		{dev: "nvme2n1", link: "nvme-nvme_card_SN0"},
	})
	_, emptyDir := newFakeByID(t, nil)

	tests := []struct {
		name    string
		hostDir string
		want    int
	}{
		{
			name:    "matching_links_only",
			hostDir: byIDDir,
			want:    4,
		},
		{
			name:    "empty_dir",
			hostDir: emptyDir,
			want:    0,
		},
		{
			name:    "missing_dir",
			hostDir: filepath.Join(t.TempDir(), "does-not-exist"),
			want:    0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := presentLSSDCount(tc.hostDir)
			if err != nil {
				t.Errorf("presentLSSDCount(%q) returned unexpected error: %v", tc.hostDir, err)
			} else if got != tc.want {
				t.Errorf("presentLSSDCount(%q) = %d, want %d", tc.hostDir, got, tc.want)
			}
		})
	}
}

func TestWaitForLSSDs(t *testing.T) {
	tests := []struct {
		name    string
		mds     fakeMDS
		initial []string
		delayed []string
		timeout time.Duration
	}{
		{
			name:    "no_lssds",
			mds:     fakeMDS{data: `[{"deviceName":"persistent-disk-0","interface":"NVME","type":"HYPERDISK-BALANCED"}]`},
			timeout: 0,
		},
		{
			name: "already_present",
			mds: fakeMDS{data: `[
				{"deviceName":"local-ssd-0","interface":"NVME","type":"LOCAL-SSD"},
				{"deviceName":"local-ssd-1","interface":"NVME","type":"LOCAL-SSD"},
				{"deviceName":"local-ssd-2","interface":"NVME","type":"LOCAL-SSD"}
			]`},
			initial: []string{
				"google-local-nvme-ssd-0",
				"google-local-nvme-ssd-0-part1",
				"google-local-nvme-ssd-2",
				"google-local-nvme-ssd-10", // Non-matching ID still passes because only the count is checked.
			},
			timeout: time.Second,
		},
		{
			name: "appears_after_polling",
			// Leaving initial empty starts without by-id to cover early boot.
			mds: fakeMDS{data: `[
				{"deviceName":"local-ssd-0","interface":"NVME","type":"LOCAL-SSD"},
				{"deviceName":"local-ssd-1","interface":"NVME","type":"LOCAL-SSD"}
			]`},
			delayed: []string{
				"google-local-nvme-ssd-0",
				"google-local-nvme-ssd-1",
			},
			timeout: 5 * time.Second,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			byIDDir := filepath.Join(t.TempDir(), "by-id")
			if len(tc.initial) > 0 {
				if err := os.MkdirAll(byIDDir, 0o755); err != nil {
					t.Fatal(err)
				}
				for _, link := range tc.initial {
					if err := os.WriteFile(filepath.Join(byIDDir, link), nil, 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}

			if len(tc.delayed) > 0 {
				done := make(chan struct{})
				defer func() { <-done }()
				go func() {
					defer close(done)
					for _, link := range tc.delayed {
						time.Sleep(10 * time.Millisecond)
						if err := os.MkdirAll(byIDDir, 0o755); err != nil {
							return
						}
						_ = os.WriteFile(filepath.Join(byIDDir, link), nil, 0o600)
					}
				}()
			}

			if err := waitForLSSDs(t.Context(), tc.mds, byIDDir, tc.timeout, 5*time.Millisecond, logging.NullLogger()); err != nil {
				t.Errorf("waitForLSSDs() returned unexpected error: %v", err)
			}
		})
	}
}

func TestWaitForLSSDs_Errors(t *testing.T) {
	tests := []struct {
		name           string
		useCanceledCtx bool
		mds            fakeMDS
		links          devSymlinks
		timeout        time.Duration
		wantErr        string
		wantErrIs      error
	}{
		{
			name:    "mds_error",
			mds:     fakeMDS{err: errors.New("mds unreachable")},
			timeout: time.Second,
			wantErr: "failed to count",
		},
		{
			name:    "non_nvme_interface",
			mds:     fakeMDS{data: `[{"deviceName":"local-ssd-0","interface":"SCSI","type":"LOCAL-SSD"}]`},
			timeout: time.Second,
			wantErr: "unsupported Local SSD interface",
		},
		{
			name: "extra_link",
			mds:  fakeMDS{data: `[{"deviceName":"local-ssd-0","interface":"NVME","type":"LOCAL-SSD"}]`},
			links: devSymlinks{
				{dev: "nvme0n1", link: "google-local-nvme-ssd-0"},
				{dev: "nvme1n1", link: "google-local-nvme-ssd-1"},
			},
			timeout: time.Second,
			wantErr: "unexpected Local SSD links",
		},
		{
			name: "timeout",
			mds: fakeMDS{data: `[
				{"deviceName":"local-ssd-0","interface":"NVME","type":"LOCAL-SSD"},
				{"deviceName":"local-ssd-1","interface":"NVME","type":"LOCAL-SSD"}
			]`},
			links:   devSymlinks{{dev: "nvme0n1", link: "google-local-nvme-ssd-0"}},
			timeout: 20 * time.Millisecond,
			wantErr: "not all Local SSD links appeared",
		},
		{
			name:           "context_canceled",
			useCanceledCtx: true,
			mds:            fakeMDS{data: `[{"deviceName":"local-ssd-0","interface":"NVME","type":"LOCAL-SSD"}]`},
			timeout:        5 * time.Second,
			wantErrIs:      context.Canceled,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			if tc.useCanceledCtx {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			_, byIDDir := newFakeByID(t, tc.links)
			err := waitForLSSDs(ctx, tc.mds, byIDDir, tc.timeout, 5*time.Millisecond, logging.NullLogger())
			if tc.wantErrIs != nil {
				if !errors.Is(err, tc.wantErrIs) {
					t.Errorf("waitForLSSDs() error = %v, want %v", err, tc.wantErrIs)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("waitForLSSDs() error = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}
