package launcher

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func TestGB300FabricPathsLiveUnderFabricDir(t *testing.T) {
	want := []gb300FabricPath{
		{hostPath: "/usr/bin/nvidia-imex", containerPath: "/usr/local/nvidia/fabric/bin/nvidia-imex"},
		{hostPath: "/usr/bin/nvidia-imex-ctl", containerPath: "/usr/local/nvidia/fabric/bin/nvidia-imex-ctl"},
		{hostPath: "/usr/share/oem/nvidia-mnccd/rootfs/usr/bin/nvidia-mnccd", containerPath: "/usr/local/nvidia/fabric/bin/nvidia-mnccd"},
		{hostPath: "/usr/share/oem/nvidia-imex/etc", containerPath: "/usr/local/nvidia/fabric/etc/nvidia-imex", isDir: true},
		{hostPath: "/usr/share/oem/nvidia-mnccd/etc", containerPath: "/usr/local/nvidia/fabric/etc/nvidia-mnccd", isDir: true},
	}
	if diff := cmp.Diff(want, gb300FabricPaths, cmp.AllowUnexported(gb300FabricPath{})); diff != "" {
		t.Errorf("gb300FabricPaths mismatch (-want +got):\n%s", diff)
	}
}

func TestGB300FabricMounts(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "nvidia-imex")
	if err := os.WriteFile(regular, []byte("#!/bin/true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "nvidia-imex-link")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	etc := filepath.Join(dir, "etc")
	if err := os.Mkdir(etc, 0o755); err != nil {
		t.Fatal(err)
	}
	etcLink := filepath.Join(dir, "etc-link")
	if err := os.Symlink(etc, etcLink); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "nvidia-imex-ctl")

	mount := func(opt, src, dst string) specs.Mount {
		return specs.Mount{Type: "bind", Source: src, Destination: dst, Options: []string{opt, "ro"}}
	}

	tests := []struct {
		name          string
		paths         []gb300FabricPath
		stat          func(string) (os.FileInfo, error)
		wantMounts    []specs.Mount
		wantSkipped   int
		wantErrIs     error
		wantErrSubstr string
	}{
		{
			name:       "regular file is bind-mounted read-only",
			paths:      []gb300FabricPath{{hostPath: regular, containerPath: "/c/nvidia-imex"}},
			stat:       os.Stat,
			wantMounts: []specs.Mount{mount("bind", regular, "/c/nvidia-imex")},
		},
		{
			name:       "nil stat defaults to os.Stat",
			paths:      []gb300FabricPath{{hostPath: regular, containerPath: "/c/nvidia-imex"}},
			wantMounts: []specs.Mount{mount("bind", regular, "/c/nvidia-imex")},
		},
		{
			name:       "symlink to regular file is mounted",
			paths:      []gb300FabricPath{{hostPath: link, containerPath: "/c/nvidia-imex"}},
			stat:       os.Stat,
			wantMounts: []specs.Mount{mount("bind", link, "/c/nvidia-imex")},
		},
		{
			name:       "directory is rbind-mounted read-only",
			paths:      []gb300FabricPath{{hostPath: etc, containerPath: "/c/etc", isDir: true}},
			stat:       os.Stat,
			wantMounts: []specs.Mount{mount("rbind", etc, "/c/etc")},
		},
		{
			name:       "symlink to directory is rbind-mounted read-only",
			paths:      []gb300FabricPath{{hostPath: etcLink, containerPath: "/c/etc", isDir: true}},
			stat:       os.Stat,
			wantMounts: []specs.Mount{mount("rbind", etcLink, "/c/etc")},
		},
		{
			name:        "missing path is skipped",
			paths:       []gb300FabricPath{{hostPath: missing, containerPath: "/c/nvidia-imex-ctl"}},
			stat:        os.Stat,
			wantSkipped: 1,
			wantErrIs:   fs.ErrNotExist,
		},
		{
			name:          "directory where a file is expected is skipped",
			paths:         []gb300FabricPath{{hostPath: etc, containerPath: "/c/nvidia-mnccd"}},
			stat:          os.Stat,
			wantSkipped:   1,
			wantErrSubstr: "not a regular file",
		},
		{
			name:          "file where a directory is expected is skipped",
			paths:         []gb300FabricPath{{hostPath: regular, containerPath: "/c/etc", isDir: true}},
			stat:          os.Stat,
			wantSkipped:   1,
			wantErrSubstr: "not a directory",
		},
		{
			name: "skipped path does not drop the others",
			paths: []gb300FabricPath{
				{hostPath: regular, containerPath: "/c/nvidia-imex"},
				{hostPath: missing, containerPath: "/c/nvidia-imex-ctl"},
				{hostPath: etc, containerPath: "/c/etc", isDir: true},
			},
			stat:        os.Stat,
			wantMounts:  []specs.Mount{mount("bind", regular, "/c/nvidia-imex"), mount("rbind", etc, "/c/etc")},
			wantSkipped: 1,
			wantErrIs:   fs.ErrNotExist,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotMounts, gotSkipped := gb300FabricMounts(tc.paths, tc.stat)
			if diff := cmp.Diff(tc.wantMounts, gotMounts); diff != "" {
				t.Errorf("gb300FabricMounts() mounts mismatch (-want +got):\n%s", diff)
			}
			if len(gotSkipped) != tc.wantSkipped {
				t.Fatalf("gb300FabricMounts() skipped %d paths (%v), want %d", len(gotSkipped), gotSkipped, tc.wantSkipped)
			}
			if tc.wantErrIs != nil && !errors.Is(gotSkipped[0], tc.wantErrIs) {
				t.Errorf("gb300FabricMounts() skip error = %v, want error wrapping %v", gotSkipped[0], tc.wantErrIs)
			}
			if tc.wantErrSubstr != "" && !strings.Contains(gotSkipped[0].Error(), tc.wantErrSubstr) {
				t.Errorf("gb300FabricMounts() skip error = %v, want substring %q", gotSkipped[0], tc.wantErrSubstr)
			}
		})
	}
}

func TestGB300FabricDevs(t *testing.T) {
	type capFixture struct {
		procContent string
		createNode  bool
		nodeIsDir   bool
	}

	tests := []struct {
		name           string
		missingChanDir bool
		channels       []string
		nonCharChans   []string
		extraChanFiles []string
		caps           map[string]capFixture
		extraCapNodes  []string
		wantDevs       func(devRoot string) []string
		wantSkipped    int
		wantErrIs      error
		wantErrSubstrs []string
	}{
		{
			name:     "0 channels and both capabilities ok",
			channels: nil,
			caps: map[string]capFixture{
				"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 15\nDeviceFileMode: 292\n", createNode: true},
				"mncc-mgmt":        {procContent: "DeviceFileMinor: 21\nDeviceFileMode: 292\n", createNode: true},
			},
			extraCapNodes: []string{"nvidia-cap99"},
			wantDevs: func(devRoot string) []string {
				return []string{
					filepath.Join(devRoot, "nvidia-caps", "nvidia-cap15"),
					filepath.Join(devRoot, "nvidia-caps", "nvidia-cap21"),
				}
			},
		},
		{
			name:           "1 channel and extra non-matching file ignored",
			channels:       []string{"channel0"},
			extraChanFiles: []string{"readme"},
			caps: map[string]capFixture{
				"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 15\n", createNode: true},
				"mncc-mgmt":        {procContent: "DeviceFileMinor: 21\n", createNode: true},
			},
			wantDevs: func(devRoot string) []string {
				return []string{
					filepath.Join(devRoot, "nvidia-caps-imex-channels", "channel0"),
					filepath.Join(devRoot, "nvidia-caps", "nvidia-cap15"),
					filepath.Join(devRoot, "nvidia-caps", "nvidia-cap21"),
				}
			},
		},
		{
			name:     "2 channels ok",
			channels: []string{"channel0", "channel1"},
			caps: map[string]capFixture{
				"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 0\n", createNode: true},
				"mncc-mgmt":        {procContent: "DeviceFileMinor: 1\n", createNode: true},
			},
			wantDevs: func(devRoot string) []string {
				return []string{
					filepath.Join(devRoot, "nvidia-caps-imex-channels", "channel0"),
					filepath.Join(devRoot, "nvidia-caps-imex-channels", "channel1"),
					filepath.Join(devRoot, "nvidia-caps", "nvidia-cap0"),
					filepath.Join(devRoot, "nvidia-caps", "nvidia-cap1"),
				}
			},
		},
		{
			name:         "non-char channel entry is skipped without dropping valid channel",
			channels:     []string{"channel1"},
			nonCharChans: []string{"channel0"},
			caps: map[string]capFixture{
				"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 15\n", createNode: true},
				"mncc-mgmt":        {procContent: "DeviceFileMinor: 21\n", createNode: true},
			},
			wantDevs: func(devRoot string) []string {
				return []string{
					filepath.Join(devRoot, "nvidia-caps-imex-channels", "channel1"),
					filepath.Join(devRoot, "nvidia-caps", "nvidia-cap15"),
					filepath.Join(devRoot, "nvidia-caps", "nvidia-cap21"),
				}
			},
			wantSkipped:    1,
			wantErrSubstrs: []string{"not a character device"},
		},
		{
			name:           "missing channels dir is skipped",
			missingChanDir: true,
			caps: map[string]capFixture{
				"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 15\n", createNode: true},
				"mncc-mgmt":        {procContent: "DeviceFileMinor: 21\n", createNode: true},
			},
			wantDevs: func(devRoot string) []string {
				return []string{
					filepath.Join(devRoot, "nvidia-caps", "nvidia-cap15"),
					filepath.Join(devRoot, "nvidia-caps", "nvidia-cap21"),
				}
			},
			wantSkipped: 1,
			wantErrIs:   fs.ErrNotExist,
		},
		{
			name:     "missing proc file is skipped",
			channels: []string{"channel0"},
			caps: map[string]capFixture{
				"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 15\n", createNode: true},
				// mncc-mgmt proc file omitted (e.g. driver < 620.51)
			},
			wantDevs: func(devRoot string) []string {
				return []string{
					filepath.Join(devRoot, "nvidia-caps-imex-channels", "channel0"),
					filepath.Join(devRoot, "nvidia-caps", "nvidia-cap15"),
				}
			},
			wantSkipped: 1,
			wantErrIs:   fs.ErrNotExist,
		},
		{
			name: "missing DeviceFileMinor line is skipped",
			caps: map[string]capFixture{
				"fabric-imex-mgmt": {procContent: "DeviceFileMode: 292\n"},
				"mncc-mgmt":        {procContent: "DeviceFileMinor: 21\n", createNode: true},
			},
			wantDevs: func(devRoot string) []string {
				return []string{filepath.Join(devRoot, "nvidia-caps", "nvidia-cap21")}
			},
			wantSkipped:    1,
			wantErrSubstrs: []string{"missing DeviceFileMinor"},
		},
		{
			name: "malformed DeviceFileMinor is skipped",
			caps: map[string]capFixture{
				"fabric-imex-mgmt": {procContent: "DeviceFileMinor: not-a-number\n"},
				"mncc-mgmt":        {procContent: "DeviceFileMinor: -1\n"},
			},
			wantSkipped:    2,
			wantErrSubstrs: []string{"invalid DeviceFileMinor"},
		},
		{
			name: "missing cap device node is skipped",
			caps: map[string]capFixture{
				"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 15\n", createNode: false},
				"mncc-mgmt":        {procContent: "DeviceFileMinor: 21\n", createNode: true},
			},
			wantDevs: func(devRoot string) []string {
				return []string{filepath.Join(devRoot, "nvidia-caps", "nvidia-cap21")}
			},
			wantSkipped: 1,
			wantErrIs:   fs.ErrNotExist,
		},
		{
			name: "non-char cap device node is skipped",
			caps: map[string]capFixture{
				"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 15\n", createNode: true, nodeIsDir: true},
				"mncc-mgmt":        {procContent: "DeviceFileMinor: 21\n", createNode: true},
			},
			wantDevs: func(devRoot string) []string {
				return []string{filepath.Join(devRoot, "nvidia-caps", "nvidia-cap21")}
			},
			wantSkipped:    1,
			wantErrSubstrs: []string{"not a character device"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			devRoot := filepath.Join(root, "dev")
			procRoot := filepath.Join(root, "proc")
			capsDevDir := filepath.Join(devRoot, "nvidia-caps")
			capsProcDir := filepath.Join(procRoot, "driver", "nvidia", "capabilities")
			if err := os.MkdirAll(capsDevDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(capsProcDir, 0o755); err != nil {
				t.Fatal(err)
			}

			if !tc.missingChanDir {
				chanDir := filepath.Join(devRoot, "nvidia-caps-imex-channels")
				if err := os.MkdirAll(chanDir, 0o755); err != nil {
					t.Fatal(err)
				}
				for _, ch := range tc.channels {
					if err := os.WriteFile(filepath.Join(chanDir, ch), nil, 0o666); err != nil {
						t.Fatal(err)
					}
				}
				for _, ch := range tc.nonCharChans {
					if err := os.Mkdir(filepath.Join(chanDir, ch), 0o755); err != nil {
						t.Fatal(err)
					}
				}
				for _, extra := range tc.extraChanFiles {
					if err := os.WriteFile(filepath.Join(chanDir, extra), nil, 0o666); err != nil {
						t.Fatal(err)
					}
				}
			}

			for capName, fx := range tc.caps {
				if err := os.WriteFile(filepath.Join(capsProcDir, capName), []byte(fx.procContent), 0o444); err != nil {
					t.Fatal(err)
				}
				if fx.createNode {
					minor, err := parseNvidiaCapMinor([]byte(fx.procContent))
					if err != nil {
						t.Fatalf("test fixture %s has invalid procContent: %v", capName, err)
					}
					nodePath := filepath.Join(capsDevDir, "nvidia-cap"+strconv.Itoa(minor))
					if fx.nodeIsDir {
						if err := os.Mkdir(nodePath, 0o755); err != nil {
							t.Fatal(err)
						}
					} else if err := os.WriteFile(nodePath, nil, 0o666); err != nil {
						t.Fatal(err)
					}
				}
			}
			for _, extra := range tc.extraCapNodes {
				if err := os.WriteFile(filepath.Join(capsDevDir, extra), nil, 0o666); err != nil {
					t.Fatal(err)
				}
			}

			gotDevs, gotSkipped := gb300FabricDevs(devRoot, procRoot, fakeDevStat)
			var wantDevs []string
			if tc.wantDevs != nil {
				wantDevs = tc.wantDevs(devRoot)
			}
			if diff := cmp.Diff(wantDevs, gotDevs); diff != "" {
				t.Errorf("gb300FabricDevs() devs mismatch (-want +got):\n%s", diff)
			}
			if len(gotSkipped) != tc.wantSkipped {
				t.Fatalf("gb300FabricDevs() skipped %d (%v), want %d", len(gotSkipped), gotSkipped, tc.wantSkipped)
			}
			if tc.wantErrIs != nil && !errors.Is(gotSkipped[0], tc.wantErrIs) {
				t.Errorf("gb300FabricDevs() skip error = %v, want error wrapping %v", gotSkipped[0], tc.wantErrIs)
			}
			for _, substr := range tc.wantErrSubstrs {
				matched := false
				for _, err := range gotSkipped {
					if strings.Contains(err.Error(), substr) {
						matched = true
						break
					}
				}
				if !matched {
					t.Errorf("gb300FabricDevs() skip errors %v missing substring %q", gotSkipped, substr)
				}
			}
		})
	}
}
