package launcher

import (
	"context"
	"errors"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/oci"
	"github.com/google/go-cmp/cmp"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

type wantSkip struct {
	errIs  error
	substr string
}

func assertSkippedErrors(t *testing.T, got []error, want []wantSkip) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d skipped error(s) (%v), want %d (%+v)", len(got), got, len(want), want)
	}
	for i, w := range want {
		if w.errIs != nil && !errors.Is(got[i], w.errIs) {
			t.Errorf("skipped[%d] = %v, want error wrapping %v", i, got[i], w.errIs)
		}
		if w.substr != "" && !strings.Contains(got[i].Error(), w.substr) {
			t.Errorf("skipped[%d] = %v, want substring %q", i, got[i], w.substr)
		}
	}
}

func TestGB300FabricMounts(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "nvidia-imex")
	if err := os.WriteFile(regular, []byte("#!/bin/true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(dir, "nvidia-mnccd")
	if err := os.WriteFile(second, []byte("#!/bin/true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "nvidia-imex-link")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(dir, "nvidia-imex-dangling")
	if err := os.Symlink("nonexistent-binary", dangling); err != nil {
		t.Fatal(err)
	}
	subdir := filepath.Join(dir, "dir")
	if err := os.Mkdir(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "nvidia-imex-ctl")
	notDirChild := filepath.Join(regular, "child")

	mount := func(src, dst string) specs.Mount {
		return specs.Mount{Type: "bind", Source: src, Destination: dst, Options: []string{"bind", "ro"}}
	}

	tests := []struct {
		name          string
		binaries      []string
		wantMounts    []specs.Mount
		wantSkipped   []wantSkip
		wantErrIs     error
		wantErrSubstr string
	}{
		{
			name:       "regular file is bind-mounted read-only",
			binaries:   []string{regular},
			wantMounts: []specs.Mount{mount(regular, "/usr/local/nvidia/fabric/bin/nvidia-imex")},
		},
		{
			name:       "symlink to regular file is mounted",
			binaries:   []string{link},
			wantMounts: []specs.Mount{mount(link, "/usr/local/nvidia/fabric/bin/nvidia-imex-link")},
		},
		{
			name:        "missing path is skipped",
			binaries:    []string{missing},
			wantSkipped: []wantSkip{{errIs: fs.ErrNotExist, substr: "cannot stat"}},
		},
		{
			name:        "missing binary before valid binary does not drop the valid binary",
			binaries:    []string{missing, regular, second},
			wantMounts:  []specs.Mount{mount(regular, "/usr/local/nvidia/fabric/bin/nvidia-imex"), mount(second, "/usr/local/nvidia/fabric/bin/nvidia-mnccd")},
			wantSkipped: []wantSkip{{errIs: fs.ErrNotExist, substr: "cannot stat"}},
		},
		{
			name:          "directory before valid binary fails closed",
			binaries:      []string{subdir, regular},
			wantErrSubstr: "not a regular file",
		},
		{
			name:          "dangling symlink fails closed",
			binaries:      []string{dangling},
			wantErrIs:     fs.ErrNotExist,
			wantErrSubstr: "cannot stat",
		},
		{
			name:          "ENOTDIR lstat error fails closed",
			binaries:      []string{notDirChild},
			wantErrIs:     syscall.ENOTDIR,
			wantErrSubstr: "cannot lstat",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotMounts, gotSkipped, err := gb300FabricMounts(tc.binaries)
			if tc.wantErrSubstr != "" || tc.wantErrIs != nil {
				if err == nil {
					t.Fatalf("gb300FabricMounts() succeeded, want error")
				}
				if tc.wantErrIs != nil && !errors.Is(err, tc.wantErrIs) {
					t.Errorf("gb300FabricMounts() err = %v, want error wrapping %v", err, tc.wantErrIs)
				}
				if tc.wantErrSubstr != "" && !strings.Contains(err.Error(), tc.wantErrSubstr) {
					t.Errorf("gb300FabricMounts() err = %v, want substring %q", err, tc.wantErrSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("gb300FabricMounts() unexpected error: %v", err)
			}
			if diff := cmp.Diff(tc.wantMounts, gotMounts); diff != "" {
				t.Errorf("gb300FabricMounts() mounts mismatch (-want +got):\n%s", diff)
			}
			assertSkippedErrors(t, gotSkipped, tc.wantSkipped)
		})
	}
}

type capFixture struct {
	procContent string
	procIsDir   bool
	nodeName    string
	nodeIsDir   bool
	nodeTarget  string
}

type channelFixture struct {
	missingDir bool
	dirAsFile  bool
	files      []string
	dirs       []string
	symlinks   map[string]string
}

type fabricDevFixture struct {
	channels           channelFixture
	caps               map[string]capFixture
	extraCapNodes      []string
	capsDirAsFile      bool
	procDevices        string
	missingProcDevices bool
}

const defaultTestProcDevices = "Character devices:\n  237 nvidia-caps-imex-channels\n  236 nvidia-caps\n"

func setupChannelFixture(t *testing.T, devRoot string, fx channelFixture) {
	t.Helper()
	if fx.missingDir {
		return
	}
	chanDir := filepath.Join(devRoot, "nvidia-caps-imex-channels")
	if fx.dirAsFile {
		if err := os.MkdirAll(devRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(chanDir, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := os.MkdirAll(chanDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range fx.files {
		if err := os.WriteFile(filepath.Join(chanDir, name), nil, 0o666); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range fx.dirs {
		if err := os.Mkdir(filepath.Join(chanDir, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for linkName, target := range fx.symlinks {
		if err := os.Symlink(target, filepath.Join(chanDir, linkName)); err != nil {
			t.Fatal(err)
		}
	}
}

func setupCapFixture(t *testing.T, devRoot, procRoot string, fx fabricDevFixture) {
	t.Helper()
	capsDevDir := filepath.Join(devRoot, "nvidia-caps")
	capsProcDir := filepath.Join(procRoot, "driver", "nvidia", "capabilities")
	if err := os.MkdirAll(devRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if fx.capsDirAsFile {
		if err := os.WriteFile(capsDevDir, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	} else if err := os.MkdirAll(capsDevDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(capsProcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if !fx.missingProcDevices {
		procDev := fx.procDevices
		if procDev == "" {
			procDev = defaultTestProcDevices
		}
		if err := os.WriteFile(filepath.Join(procRoot, "devices"), []byte(procDev), 0o444); err != nil {
			t.Fatal(err)
		}
	}
	for capName, capFx := range fx.caps {
		procPath := filepath.Join(capsProcDir, capName)
		if capFx.procIsDir {
			if err := os.Mkdir(procPath, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(procPath, []byte(capFx.procContent), 0o444); err != nil {
			t.Fatal(err)
		}
		if capFx.nodeName == "" || fx.capsDirAsFile {
			continue
		}
		nodePath := filepath.Join(capsDevDir, capFx.nodeName)
		switch {
		case capFx.nodeIsDir:
			if err := os.Mkdir(nodePath, 0o755); err != nil {
				t.Fatal(err)
			}
		case capFx.nodeTarget != "":
			if err := os.Symlink(capFx.nodeTarget, nodePath); err != nil {
				t.Fatal(err)
			}
		default:
			if err := os.WriteFile(nodePath, nil, 0o666); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !fx.capsDirAsFile {
		for _, extra := range fx.extraCapNodes {
			if err := os.WriteFile(filepath.Join(capsDevDir, extra), nil, 0o666); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func fakeFabricDevStat(devRoot string, overrides map[string]uint64) func(string) (bool, uint64, error) {
	return func(p string) (bool, uint64, error) {
		if rdev, ok := overrides[p]; ok {
			return true, rdev, nil
		}
		rel, err := filepath.Rel(devRoot, p)
		if err != nil || strings.HasPrefix(rel, "..") {
			return charDevStat(p)
		}
		fi, err := os.Stat(p)
		if err != nil {
			return false, 0, err
		}
		if !fi.Mode().IsRegular() {
			return false, 0, nil
		}
		dir, base := filepath.Split(filepath.ToSlash(rel))
		switch dir {
		case "nvidia-caps-imex-channels/":
			if m := imexChannelNameRegexp.FindStringSubmatch(base); m != nil {
				n, err := strconv.ParseUint(m[1], 10, 32)
				if err == nil {
					return true, unix.Mkdev(237, uint32(n)), nil
				}
			}
		case "nvidia-caps/":
			if after, ok := strings.CutPrefix(base, "nvidia-cap"); ok {
				n, err := strconv.ParseUint(after, 10, 32)
				if err == nil {
					return true, unix.Mkdev(236, uint32(n)), nil
				}
			}
		}
		return true, unix.Mkdev(0, 0), nil
	}
}

func TestGB300FabricDevs(t *testing.T) {
	type rdevOverride struct {
		rel   string
		major uint32
		minor uint32
	}

	tests := []struct {
		name          string
		fixture       fabricDevFixture
		customDevStat func(string) (bool, uint64, error)
		rdevOverrides []rdevOverride
		wantPaths     []string
		wantSkipped   []wantSkip
		wantErrIs     error
		wantErrSubstr string
	}{
		{
			name: "0 channels and both capabilities ok",
			fixture: fabricDevFixture{
				caps: map[string]capFixture{
					"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 15\nDeviceFileMode: 292\n", nodeName: "nvidia-cap15"},
					"mncc-mgmt":        {procContent: "DeviceFileMinor: 21\nDeviceFileMode: 292\n", nodeName: "nvidia-cap21"},
				},
				extraCapNodes: []string{"nvidia-cap99"},
			},
			wantPaths: []string{"nvidia-caps/nvidia-cap15", "nvidia-caps/nvidia-cap21"},
		},
		{
			name: "empty channels dir and missing caps do not read proc devices",
			fixture: fabricDevFixture{
				channels:           channelFixture{files: []string{"readme"}},
				missingProcDevices: true,
			},
			wantSkipped: []wantSkip{
				{errIs: fs.ErrNotExist, substr: "fabric-imex-mgmt"},
				{errIs: fs.ErrNotExist, substr: "mncc-mgmt"},
			},
		},
		{
			name: "1 channel and extra non-matching files ignored",
			fixture: fabricDevFixture{
				channels: channelFixture{files: []string{"aaa", "channel", "channel0", "channel0.bak", "readme", "xchannel0"}},
				caps: map[string]capFixture{
					"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 15\n", nodeName: "nvidia-cap15"},
					"mncc-mgmt":        {procContent: "DeviceFileMinor: 21\n", nodeName: "nvidia-cap21"},
				},
			},
			wantPaths: []string{"nvidia-caps-imex-channels/channel0", "nvidia-caps/nvidia-cap15", "nvidia-caps/nvidia-cap21"},
		},
		{
			name: "2 channels ok",
			fixture: fabricDevFixture{
				channels: channelFixture{files: []string{"channel0", "channel1"}},
				caps: map[string]capFixture{
					"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 0\n", nodeName: "nvidia-cap0"},
					"mncc-mgmt":        {procContent: "DeviceFileMinor: 1\n", nodeName: "nvidia-cap1"},
				},
			},
			wantPaths: []string{"nvidia-caps-imex-channels/channel0", "nvidia-caps-imex-channels/channel1", "nvidia-caps/nvidia-cap0", "nvidia-caps/nvidia-cap1"},
		},
		{
			name: "missing channels dir and missing mncc-mgmt proc file both accumulate skips",
			fixture: fabricDevFixture{
				channels: channelFixture{missingDir: true},
				caps: map[string]capFixture{
					"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 15\n", nodeName: "nvidia-cap15"},
				},
			},
			wantPaths: []string{"nvidia-caps/nvidia-cap15"},
			wantSkipped: []wantSkip{
				{errIs: fs.ErrNotExist, substr: "nvidia-caps-imex-channels"},
				{errIs: fs.ErrNotExist, substr: "mncc-mgmt"},
			},
		},
		{
			name: "missing fabric-imex-mgmt proc file skips and keeps mncc-mgmt",
			fixture: fabricDevFixture{
				caps: map[string]capFixture{
					"mncc-mgmt": {procContent: "DeviceFileMinor: 21\n", nodeName: "nvidia-cap21"},
				},
			},
			wantPaths: []string{"nvidia-caps/nvidia-cap21"},
			wantSkipped: []wantSkip{
				{errIs: fs.ErrNotExist, substr: "fabric-imex-mgmt"},
			},
		},
		{
			name: "missing fabric-imex-mgmt cap node skips and keeps mncc-mgmt",
			fixture: fabricDevFixture{
				caps: map[string]capFixture{
					"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 15\n"},
					"mncc-mgmt":        {procContent: "DeviceFileMinor: 21\n", nodeName: "nvidia-cap21"},
				},
			},
			wantPaths: []string{"nvidia-caps/nvidia-cap21"},
			wantSkipped: []wantSkip{
				{errIs: fs.ErrNotExist, substr: "nvidia-cap15"},
			},
		},
		{
			name: "CRLF proc file with DeviceFileMinor on line 2 parses",
			fixture: fabricDevFixture{
				caps: map[string]capFixture{
					"fabric-imex-mgmt": {procContent: "DeviceFileMode: 292\r\nDeviceFileMinor: 15\r\n", nodeName: "nvidia-cap15"},
					"mncc-mgmt":        {procContent: "DeviceFileMode: 292\r\nDeviceFileMinor: 21\r\n", nodeName: "nvidia-cap21"},
				},
			},
			wantPaths: []string{"nvidia-caps/nvidia-cap15", "nvidia-caps/nvidia-cap21"},
		},
		{
			name:          "unreadable channels dir fails closed",
			fixture:       fabricDevFixture{channels: channelFixture{dirAsFile: true}},
			wantErrIs:     syscall.ENOTDIR,
			wantErrSubstr: "cannot read",
		},
		{
			name:          "channel minor overflow fails closed",
			fixture:       fabricDevFixture{channels: channelFixture{files: []string{"channel99999999999"}}},
			wantErrIs:     strconv.ErrRange,
			wantErrSubstr: "invalid IMEX channel number",
		},
		{
			name:          "dangling channel symlink fails closed",
			fixture:       fabricDevFixture{channels: channelFixture{symlinks: map[string]string{"channel1": "nonexistent-target"}}},
			wantErrIs:     fs.ErrNotExist,
			wantErrSubstr: "cannot resolve",
		},
		{
			name:          "non-char channel directory fails closed",
			fixture:       fabricDevFixture{channels: channelFixture{dirs: []string{"channel0"}}},
			wantErrSubstr: "not a character device",
		},
		{
			name:          "charDevStat rejects regular channel file",
			fixture:       fabricDevFixture{channels: channelFixture{files: []string{"channel0"}}},
			customDevStat: charDevStat,
			wantErrSubstr: "not a character device",
		},
		{
			name:    "channel devStat error fails closed",
			fixture: fabricDevFixture{channels: channelFixture{files: []string{"channel0"}}},
			customDevStat: func(string) (bool, uint64, error) {
				return false, 0, errors.New("stat io error")
			},
			wantErrSubstr: "stat io error",
		},
		{
			name: "channel1 symlink to nvidia-cap15 fails closed on wrong major and minor",
			fixture: fabricDevFixture{
				channels: channelFixture{symlinks: map[string]string{"channel1": "../nvidia-caps/nvidia-cap15"}},
				caps: map[string]capFixture{
					"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 15\n", nodeName: "nvidia-cap15"},
				},
			},
			wantErrSubstr: "236:15, want 237:1",
		},
		{
			name: "channel15 symlink to nvidia-cap15 fails closed on same minor wrong major",
			fixture: fabricDevFixture{
				channels: channelFixture{symlinks: map[string]string{"channel15": "../nvidia-caps/nvidia-cap15"}},
				caps: map[string]capFixture{
					"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 15\n", nodeName: "nvidia-cap15"},
				},
			},
			wantErrSubstr: "236:15, want 237:15",
		},
		{
			name: "channel0 symlink to /dev/null fails closed on wrong major and minor",
			fixture: fabricDevFixture{
				channels: channelFixture{symlinks: map[string]string{"channel0": "/dev/null"}},
			},
			wantErrSubstr: "1:3, want 237:0",
		},
		{
			name: "missing proc devices when channel present fails closed",
			fixture: fabricDevFixture{
				channels:           channelFixture{files: []string{"channel0"}},
				missingProcDevices: true,
			},
			wantErrIs:     fs.ErrNotExist,
			wantErrSubstr: "cannot read",
		},
		{
			name: "missing imex driver in proc devices fails closed",
			fixture: fabricDevFixture{
				channels:    channelFixture{files: []string{"channel0"}},
				procDevices: "Character devices:\n  236 nvidia-caps\n",
			},
			wantErrSubstr: "missing character device driver \"nvidia-caps-imex-channels\"",
		},
		{
			name: "unreadable proc capability file fails closed",
			fixture: fabricDevFixture{
				caps: map[string]capFixture{
					"fabric-imex-mgmt": {procIsDir: true},
				},
			},
			wantErrIs:     syscall.EISDIR,
			wantErrSubstr: "cannot read",
		},
		{
			name: "missing DeviceFileMinor line fails closed",
			fixture: fabricDevFixture{
				caps: map[string]capFixture{
					"fabric-imex-mgmt": {procContent: "DeviceFileMode: 292\n"},
				},
			},
			wantErrSubstr: "missing DeviceFileMinor",
		},
		{
			name: "malformed DeviceFileMinor fails closed",
			fixture: fabricDevFixture{
				caps: map[string]capFixture{
					"fabric-imex-mgmt": {procContent: "DeviceFileMinor: not-a-number\n"},
				},
			},
			wantErrSubstr: "invalid DeviceFileMinor",
		},
		{
			name: "ENOTDIR on cap device node lstat fails closed",
			fixture: fabricDevFixture{
				capsDirAsFile: true,
				caps: map[string]capFixture{
					"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 15\n"},
				},
			},
			wantErrIs:     syscall.ENOTDIR,
			wantErrSubstr: "cannot lstat",
		},
		{
			name: "non-char cap device node fails closed",
			fixture: fabricDevFixture{
				caps: map[string]capFixture{
					"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 15\n", nodeName: "nvidia-cap15", nodeIsDir: true},
				},
			},
			wantErrSubstr: "not a character device",
		},
		{
			name: "dangling cap symlink fails closed",
			fixture: fabricDevFixture{
				caps: map[string]capFixture{
					"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 15\n", nodeName: "nvidia-cap15", nodeTarget: "nonexistent"},
				},
			},
			wantErrIs:     fs.ErrNotExist,
			wantErrSubstr: "cannot resolve",
		},
		{
			name: "cap node same major wrong minor fails closed",
			fixture: fabricDevFixture{
				caps: map[string]capFixture{
					"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 15\n", nodeName: "nvidia-cap15"},
				},
			},
			rdevOverrides: []rdevOverride{{rel: "nvidia-caps/nvidia-cap15", major: 236, minor: 21}},
			wantErrSubstr: "236:21, want 236:15",
		},
		{
			name: "missing proc devices when cap node present fails closed",
			fixture: fabricDevFixture{
				missingProcDevices: true,
				caps: map[string]capFixture{
					"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 15\n", nodeName: "nvidia-cap15"},
				},
			},
			wantErrIs:     fs.ErrNotExist,
			wantErrSubstr: "cannot read",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			devRoot := filepath.Join(root, "dev")
			procRoot := filepath.Join(root, "proc")
			setupChannelFixture(t, devRoot, tc.fixture.channels)
			setupCapFixture(t, devRoot, procRoot, tc.fixture)

			devStat := tc.customDevStat
			if devStat == nil {
				overrides := make(map[string]uint64, len(tc.rdevOverrides))
				for _, ov := range tc.rdevOverrides {
					overrides[filepath.Join(devRoot, ov.rel)] = unix.Mkdev(ov.major, ov.minor)
				}
				devStat = fakeFabricDevStat(devRoot, overrides)
			}

			gotDevs, gotSkipped, err := gb300IMEXChannelDevs(devRoot, procRoot, devStat)
			if err == nil {
				var capDevs []gb300FabricDevice
				var capSkipped []error
				capDevs, capSkipped, err = gb300CapDevs(devRoot, procRoot, devStat)
				gotDevs = append(gotDevs, capDevs...)
				gotSkipped = append(gotSkipped, capSkipped...)
			}

			if tc.wantErrSubstr != "" || tc.wantErrIs != nil {
				if err == nil {
					t.Fatalf("discovery succeeded (devs=%v skipped=%v), want error", gotDevs, gotSkipped)
				}
				if tc.wantErrIs != nil && !errors.Is(err, tc.wantErrIs) {
					t.Errorf("discovery err = %v, want error wrapping %v", err, tc.wantErrIs)
				}
				if tc.wantErrSubstr != "" && !strings.Contains(err.Error(), tc.wantErrSubstr) {
					t.Errorf("discovery err = %v, want substring %q", err, tc.wantErrSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("discovery unexpected error: %v", err)
			}

			var wantDevs []gb300FabricDevice
			for _, rel := range tc.wantPaths {
				p := filepath.Join(devRoot, rel)
				wantDevs = append(wantDevs, gb300FabricDevice{hostPath: p, containerPath: p})
			}
			if diff := cmp.Diff(wantDevs, gotDevs, cmp.AllowUnexported(gb300FabricDevice{})); diff != "" {
				t.Errorf("fabric devs mismatch (-want +got):\n%s", diff)
			}
			assertSkippedErrors(t, gotSkipped, tc.wantSkipped)
		})
	}
}

func TestGB300FabricDevs_Symlink(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	devRoot := filepath.Join(root, "dev")
	procRoot := filepath.Join(root, "proc")
	setupChannelFixture(t, devRoot, channelFixture{symlinks: map[string]string{"channel3": "/dev/null"}})
	setupCapFixture(t, devRoot, procRoot, fabricDevFixture{
		caps: map[string]capFixture{
			"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 5\n", nodeName: "nvidia-cap5", nodeTarget: "/dev/zero"},
			"mncc-mgmt":        {procContent: "DeviceFileMinor: 8\n", nodeName: "nvidia-cap8", nodeTarget: "/dev/random"},
		},
		procDevices: "Character devices:\n  1 nvidia-caps-imex-channels\n  1 nvidia-caps\n",
	})

	gotDevs, gotSkipped, err := gb300IMEXChannelDevs(devRoot, procRoot, charDevStat)
	if err != nil {
		t.Fatalf("gb300IMEXChannelDevs() unexpected error: %v", err)
	}
	capDevs, capSkipped, err := gb300CapDevs(devRoot, procRoot, charDevStat)
	if err != nil {
		t.Fatalf("gb300CapDevs() unexpected error: %v", err)
	}
	gotDevs = append(gotDevs, capDevs...)
	gotSkipped = append(gotSkipped, capSkipped...)

	if len(gotSkipped) != 0 {
		t.Fatalf("unexpected skipped errors: %v", gotSkipped)
	}
	wantDevs := []gb300FabricDevice{
		{hostPath: "/dev/null", containerPath: filepath.Join(devRoot, "nvidia-caps-imex-channels", "channel3")},
		{hostPath: "/dev/zero", containerPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap5")},
		{hostPath: "/dev/random", containerPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap8")},
	}
	if diff := cmp.Diff(wantDevs, gotDevs, cmp.AllowUnexported(gb300FabricDevice{})); diff != "" {
		t.Errorf("symlink devs mismatch (-want +got):\n%s", diff)
	}
}

func setupFabricSpecFixture(t *testing.T, presentBins []string, missingBin string, chanFx channelFixture, caps map[string]capFixture, procDevices string) gb300FabricConfig {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	var binaries []string
	for _, name := range presentBins {
		p := filepath.Join(binDir, name)
		if err := os.WriteFile(p, []byte("#!/bin/true\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		binaries = append(binaries, p)
	}
	if missingBin != "" {
		binaries = append(binaries, filepath.Join(binDir, missingBin))
	}
	devRoot := filepath.Join(root, "dev")
	procRoot := filepath.Join(root, "proc")
	setupChannelFixture(t, devRoot, chanFx)
	setupCapFixture(t, devRoot, procRoot, fabricDevFixture{
		caps:        caps,
		procDevices: procDevices,
	})
	return gb300FabricConfig{
		binaries: binaries,
		devRoot:  devRoot,
		procRoot: procRoot,
		devStat:  charDevStat,
	}
}

func assertSubstrInLogs(t *testing.T, entries []string, want []string) {
	t.Helper()
	for _, substr := range want {
		if !slices.ContainsFunc(entries, func(s string) bool { return strings.Contains(s, substr) }) {
			t.Errorf("logs %q missing substring %q", entries, substr)
		}
	}
}

func assertFabricBinMountsInSpec(t *testing.T, gotSpec specs.Spec, binDir string, bins []string) {
	t.Helper()
	for _, bin := range bins {
		want := specs.Mount{
			Type:        "bind",
			Source:      filepath.Join(binDir, bin),
			Destination: "/usr/local/nvidia/fabric/bin/" + bin,
			Options:     []string{"bind", "ro"},
		}
		if !slices.ContainsFunc(gotSpec.Mounts, func(m specs.Mount) bool { return cmp.Equal(m, want) }) {
			t.Errorf("missing mount %+v in %+v", want, gotSpec.Mounts)
		}
	}
}

func TestGB300FabricSpecOpts(t *testing.T) {
	ctx := namespaces.WithNamespace(context.Background(), "default")
	allBins := []string{"nvidia-imex", "nvidia-imex-ctl", "nvidia-mnccd"}
	allCaps := map[string]capFixture{
		"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 5\n", nodeName: "nvidia-cap5", nodeTarget: "/dev/zero"},
		"mncc-mgmt":        {procContent: "DeviceFileMinor: 8\n", nodeName: "nvidia-cap8", nodeTarget: "/dev/random"},
	}
	procDevices := "Character devices:\n  1 nvidia-caps-imex-channels\n  1 nvidia-caps\n"

	t.Run("root_mounts_all_binaries_channels_and_caps", func(t *testing.T) {
		cfg := setupFabricSpecFixture(t, allBins, "", channelFixture{symlinks: map[string]string{"channel3": "/dev/null"}}, allCaps, procDevices)
		logger := &fakeLogger{}
		specOpts, err := gb300FabricSpecOpts(cfg, false, logger)
		if err != nil {
			t.Fatalf("gb300FabricSpecOpts() failed: %v", err)
		}
		gotSpec, err := applySpecOptsToSpec(ctx, append([]oci.SpecOpts{nil}, specOpts...))
		if err != nil {
			t.Fatalf("applySpecOptsToSpec() failed: %v", err)
		}
		if len(logger.errors) != 0 {
			t.Errorf("unexpected error logs: %v", logger.errors)
		}
		assertFabricBinMountsInSpec(t, gotSpec, filepath.Dir(cfg.binaries[0]), allBins)
		assertCharDeviceInSpec(t, gotSpec, "/dev/null", filepath.Join(cfg.devRoot, "nvidia-caps-imex-channels", "channel3"), "rw")
		assertCharDeviceInSpec(t, gotSpec, "/dev/zero", filepath.Join(cfg.devRoot, "nvidia-caps", "nvidia-cap5"), "rw")
		assertCharDeviceInSpec(t, gotSpec, "/dev/random", filepath.Join(cfg.devRoot, "nvidia-caps", "nvidia-cap8"), "rw")
		assertSubstrInLogs(t, logger.logs, []string{
			"GB300 CC mode: mounting " + cfg.binaries[0] + " at /usr/local/nvidia/fabric/bin/nvidia-imex",
			"GB300 CC mode: passing IMEX/MNCCD device /dev/null as " + filepath.Join(cfg.devRoot, "nvidia-caps-imex-channels", "channel3"),
			"GB300 CC mode: passing IMEX/MNCCD device /dev/zero as " + filepath.Join(cfg.devRoot, "nvidia-caps", "nvidia-cap5"),
			"GB300 CC mode: passing IMEX/MNCCD device /dev/random as " + filepath.Join(cfg.devRoot, "nvidia-caps", "nvidia-cap8"),
		})
	})

	t.Run("nonroot_skips_caps_keeps_binaries_and_channels", func(t *testing.T) {
		cfg := setupFabricSpecFixture(t, allBins, "", channelFixture{symlinks: map[string]string{"channel3": "/dev/null"}}, allCaps, procDevices)
		logger := &fakeLogger{}
		specOpts, err := gb300FabricSpecOpts(cfg, true, logger)
		if err != nil {
			t.Fatalf("gb300FabricSpecOpts() failed: %v", err)
		}
		gotSpec, err := applySpecOptsToSpec(ctx, append([]oci.SpecOpts{nil}, specOpts...))
		if err != nil {
			t.Fatalf("applySpecOptsToSpec() failed: %v", err)
		}
		assertFabricBinMountsInSpec(t, gotSpec, filepath.Dir(cfg.binaries[0]), allBins)
		assertCharDeviceInSpec(t, gotSpec, "/dev/null", filepath.Join(cfg.devRoot, "nvidia-caps-imex-channels", "channel3"), "rw")
		assertDeviceAbsentInSpec(t, gotSpec, "/dev/zero", filepath.Join(cfg.devRoot, "nvidia-caps", "nvidia-cap5"))
		assertDeviceAbsentInSpec(t, gotSpec, "/dev/random", filepath.Join(cfg.devRoot, "nvidia-caps", "nvidia-cap8"))
		assertSubstrInLogs(t, logger.errors, []string{
			"GB300 CC mode: IMEX/MNCCD capability device passthrough is not supported for non-root containers; skipping /dev/nvidia-caps nodes",
		})
	})

	t.Run("missing_mount_channel_and_cap_log_errors_without_failing", func(t *testing.T) {
		cfg := setupFabricSpecFixture(t, []string{"nvidia-imex"}, "nvidia-imex-ctl", channelFixture{missingDir: true}, map[string]capFixture{
			"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 5\n", nodeName: "nvidia-cap5", nodeTarget: "/dev/zero"},
		}, procDevices)
		logger := &fakeLogger{}
		specOpts, err := gb300FabricSpecOpts(cfg, false, logger)
		if err != nil {
			t.Fatalf("gb300FabricSpecOpts() failed: %v", err)
		}
		gotSpec, err := applySpecOptsToSpec(ctx, append([]oci.SpecOpts{nil}, specOpts...))
		if err != nil {
			t.Fatalf("applySpecOptsToSpec() failed: %v", err)
		}
		assertCharDeviceInSpec(t, gotSpec, "/dev/zero", filepath.Join(cfg.devRoot, "nvidia-caps", "nvidia-cap5"), "rw")
		assertSubstrInLogs(t, logger.errors, []string{
			"GB300 CC mode: skipping IMEX/MNCCD mount:",
			"GB300 CC mode: skipping IMEX/MNCCD device: cannot read",
			"nvidia-caps-imex-channels",
			"mncc-mgmt",
		})
	})

	t.Run("fatal_mount_error_fails_closed", func(t *testing.T) {
		dir := t.TempDir()
		cfg := gb300FabricConfig{binaries: []string{dir}, devRoot: dir, procRoot: dir, devStat: charDevStat}
		if _, err := gb300FabricSpecOpts(cfg, false, &fakeLogger{}); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("gb300FabricSpecOpts() error = %v, want 'not a regular file'", err)
		}
	})

	t.Run("fatal_channel_error_fails_closed", func(t *testing.T) {
		cfg := setupFabricSpecFixture(t, nil, "", channelFixture{symlinks: map[string]string{"channel3": "nonexistent"}}, nil, procDevices)
		if _, err := gb300FabricSpecOpts(cfg, false, &fakeLogger{}); err == nil || !strings.Contains(err.Error(), "cannot resolve") {
			t.Fatalf("gb300FabricSpecOpts() error = %v, want 'cannot resolve'", err)
		}
	})

	t.Run("fatal_cap_error_fails_closed", func(t *testing.T) {
		cfg := setupFabricSpecFixture(t, nil, "", channelFixture{missingDir: true}, map[string]capFixture{
			"fabric-imex-mgmt": {procContent: "DeviceFileMinor: bad\n"},
		}, procDevices)
		if _, err := gb300FabricSpecOpts(cfg, false, &fakeLogger{}); err == nil || !strings.Contains(err.Error(), "invalid DeviceFileMinor") {
			t.Fatalf("gb300FabricSpecOpts() error = %v, want 'invalid DeviceFileMinor'", err)
		}
	})
}

func TestParseNvidiaCapMinor(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		want          uint32
		wantErrSubstr string
	}{
		{name: "zero", input: "DeviceFileMinor: 0\n", want: 0},
		{name: "single digit", input: "DeviceFileMinor: 9\n", want: 9},
		{name: "typical minor", input: "DeviceFileMinor: 15\nDeviceFileMode: 292\nDeviceFileModify: 0\n", want: 15},
		{name: "whitespace and tabs", input: "  \t DeviceFileMinor:   \t 42 \t \n", want: 42},
		{name: "max uint32", input: "DeviceFileMinor: " + strconv.FormatUint(math.MaxUint32, 10) + "\n", want: math.MaxUint32},
		{name: "CRLF", input: "DeviceFileMinor: 15\r\nDeviceFileMode: 292\r\n", want: 15},
		{name: "line 2", input: "DeviceFileMode: 292\nDeviceFileMinor: 21\n", want: 21},
		{name: "negative one", input: "DeviceFileMinor: -1\n", wantErrSubstr: "invalid DeviceFileMinor"},
		{name: "negative zero", input: "DeviceFileMinor: -0\n", wantErrSubstr: "invalid DeviceFileMinor"},
		{name: "plus sign", input: "DeviceFileMinor: +5\n", wantErrSubstr: "invalid DeviceFileMinor"},
		{name: "hexadecimal", input: "DeviceFileMinor: 0x10\n", wantErrSubstr: "invalid DeviceFileMinor"},
		{name: "underscore", input: "DeviceFileMinor: 1_0\n", wantErrSubstr: "invalid DeviceFileMinor"},
		{name: "non-numeric", input: "DeviceFileMinor: not-a-number\n", wantErrSubstr: "invalid DeviceFileMinor"},
		{name: "empty value", input: "DeviceFileMinor:   \n", wantErrSubstr: "invalid DeviceFileMinor"},
		{name: "uint32 overflow", input: "DeviceFileMinor: " + strconv.FormatUint(uint64(math.MaxUint32)+1, 10) + "\n", wantErrSubstr: "invalid DeviceFileMinor"},
		{name: "huge overflow", input: "DeviceFileMinor: 99999999999999999999999999\n", wantErrSubstr: "invalid DeviceFileMinor"},
		{name: "missing DeviceFileMinor", input: "DeviceFileMode: 292\nDeviceFileModify: 0\n", wantErrSubstr: "missing DeviceFileMinor"},
		{name: "empty file", input: "", wantErrSubstr: "missing DeviceFileMinor"},
		{name: "duplicate DeviceFileMinor", input: "DeviceFileMinor: 15\nDeviceFileMinor: 21\n", wantErrSubstr: "duplicate DeviceFileMinor"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseNvidiaCapMinor([]byte(tc.input))
			if tc.wantErrSubstr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrSubstr) {
					t.Fatalf("parseNvidiaCapMinor(%q) = (%d, %v), want error containing %q", tc.input, got, err, tc.wantErrSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseNvidiaCapMinor(%q) unexpected error: %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("parseNvidiaCapMinor(%q) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}

func TestParseCharDeviceMajor(t *testing.T) {
	const driver = "nvidia-caps"
	tests := []struct {
		name          string
		input         string
		want          uint32
		wantErrSubstr string
	}{
		{
			name:  "character devices section stops before block devices",
			input: "Character devices:\n  1 mem\n236 nvidia-caps\n\nBlock devices:\n  7 loop\n236 nvidia-caps\n",
			want:  236,
		},
		{
			name:  "CRLF and extra whitespace",
			input: "Character devices:\r\n  \t 237 \t nvidia-caps \t \r\nBlock devices:\r\n  8 sd\r\n",
			want:  237,
		},
		{
			name:  "zero major",
			input: "Character devices:\n  0 nvidia-caps\n",
			want:  0,
		},
		{
			name:  "max uint32 major",
			input: "Character devices:\n  " + strconv.FormatUint(math.MaxUint32, 10) + " nvidia-caps\n",
			want:  math.MaxUint32,
		},
		{
			name:  "single-field line before matching driver",
			input: "Character devices:\n  236\n  236 nvidia-caps\n",
			want:  236,
		},
		{
			name:          "three-field line with extra token rejected",
			input:         "Character devices:\n  236 nvidia-caps extra\n",
			wantErrSubstr: "missing character device driver",
		},
		{
			name:          "entry before Character devices section ignored",
			input:         "  236 nvidia-caps\nCharacter devices:\n  1 mem\n",
			wantErrSubstr: "missing character device driver",
		},
		{
			name:          "entry in Block devices before Character devices section ignored",
			input:         "Block devices:\n  236 nvidia-caps\nCharacter devices:\n  1 mem\n",
			wantErrSubstr: "missing character device driver",
		},
		{
			name:          "entry only in Block devices section",
			input:         "Character devices:\n  1 mem\n\nBlock devices:\n  236 nvidia-caps\n",
			wantErrSubstr: "missing character device driver",
		},
		{
			name:          "missing driver entry",
			input:         "Character devices:\n  1 mem\n  237 nvidia-caps-imex-channels\n",
			wantErrSubstr: "missing character device driver",
		},
		{
			name:          "missing Character devices section",
			input:         "Block devices:\n  236 nvidia-caps\n",
			wantErrSubstr: `missing "Character devices:" section`,
		},
		{
			name:          "duplicate driver entry",
			input:         "Character devices:\n  236 nvidia-caps\n  237 nvidia-caps\n",
			wantErrSubstr: "duplicate character device driver",
		},
		{
			name:          "negative major",
			input:         "Character devices:\n  -1 nvidia-caps\n",
			wantErrSubstr: "invalid major",
		},
		{
			name:          "plus sign major",
			input:         "Character devices:\n  +5 nvidia-caps\n",
			wantErrSubstr: "invalid major",
		},
		{
			name:          "underscore major",
			input:         "Character devices:\n  1_0 nvidia-caps\n",
			wantErrSubstr: "invalid major",
		},
		{
			name:          "non-numeric major",
			input:         "Character devices:\n  abc nvidia-caps\n",
			wantErrSubstr: "invalid major",
		},
		{
			name:          "uint32 overflow major",
			input:         "Character devices:\n  " + strconv.FormatUint(uint64(math.MaxUint32)+1, 10) + " nvidia-caps\n",
			wantErrSubstr: "invalid major",
		},
		{
			name:          "empty file",
			input:         "",
			wantErrSubstr: `missing "Character devices:" section`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseCharDeviceMajor([]byte(tc.input), driver)
			if tc.wantErrSubstr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrSubstr) {
					t.Fatalf("parseCharDeviceMajor(%q, %q) = (%d, %v), want error containing %q", tc.input, driver, got, err, tc.wantErrSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseCharDeviceMajor(%q, %q) unexpected error: %v", tc.input, driver, err)
			}
			if got != tc.want {
				t.Errorf("parseCharDeviceMajor(%q, %q) = %d, want %d", tc.input, driver, got, tc.want)
			}
		})
	}
}
