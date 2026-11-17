package launcher

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode"

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

type capFixture struct {
	procContent string
	nodeName    string
	nodeIsDir   bool
	nodeTarget  string
}

type channelFixture struct {
	missingDir bool
	files      []string
	dirs       []string
	symlinks   map[string]string
}

type fabricDevFixture struct {
	channels      channelFixture
	caps          map[string]capFixture
	extraCapNodes []string
}

func setupChannelFixture(t *testing.T, devRoot string, fx channelFixture) {
	t.Helper()
	if fx.missingDir {
		return
	}
	chanDir := filepath.Join(devRoot, "nvidia-caps-imex-channels")
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

func setupCapFixture(t *testing.T, devRoot, procRoot string, caps map[string]capFixture, extraNodes []string) {
	t.Helper()
	capsDevDir := filepath.Join(devRoot, "nvidia-caps")
	capsProcDir := filepath.Join(procRoot, "driver", "nvidia", "capabilities")
	if err := os.MkdirAll(capsDevDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(capsProcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for capName, fx := range caps {
		if err := os.WriteFile(filepath.Join(capsProcDir, capName), []byte(fx.procContent), 0o444); err != nil {
			t.Fatal(err)
		}
		if fx.nodeName == "" {
			continue
		}
		nodePath := filepath.Join(capsDevDir, fx.nodeName)
		switch {
		case fx.nodeIsDir:
			if err := os.Mkdir(nodePath, 0o755); err != nil {
				t.Fatal(err)
			}
		case fx.nodeTarget != "":
			if err := os.Symlink(fx.nodeTarget, nodePath); err != nil {
				t.Fatal(err)
			}
		default:
			if err := os.WriteFile(nodePath, nil, 0o666); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, extra := range extraNodes {
		if err := os.WriteFile(filepath.Join(capsDevDir, extra), nil, 0o666); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGB300FabricDevs(t *testing.T) {
	tests := []struct {
		name           string
		fixture        fabricDevFixture
		devStat        func(string) (bool, uint64, error)
		wantDevs       func(devRoot string) []gb300FabricDevice
		wantSkipped    int
		wantErrIs      []error
		wantErrSubstrs []string
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
			devStat: fakeDevStat,
			wantDevs: func(devRoot string) []gb300FabricDevice {
				return []gb300FabricDevice{
					{hostPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap15"), containerPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap15")},
					{hostPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap21"), containerPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap21")},
				}
			},
		},
		{
			name: "1 channel and extra non-matching file ignored",
			fixture: fabricDevFixture{
				channels: channelFixture{files: []string{"channel0", "readme"}},
				caps: map[string]capFixture{
					"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 15\n", nodeName: "nvidia-cap15"},
					"mncc-mgmt":        {procContent: "DeviceFileMinor: 21\n", nodeName: "nvidia-cap21"},
				},
			},
			devStat: fakeDevStat,
			wantDevs: func(devRoot string) []gb300FabricDevice {
				return []gb300FabricDevice{
					{hostPath: filepath.Join(devRoot, "nvidia-caps-imex-channels", "channel0"), containerPath: filepath.Join(devRoot, "nvidia-caps-imex-channels", "channel0")},
					{hostPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap15"), containerPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap15")},
					{hostPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap21"), containerPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap21")},
				}
			},
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
			devStat: fakeDevStat,
			wantDevs: func(devRoot string) []gb300FabricDevice {
				return []gb300FabricDevice{
					{hostPath: filepath.Join(devRoot, "nvidia-caps-imex-channels", "channel0"), containerPath: filepath.Join(devRoot, "nvidia-caps-imex-channels", "channel0")},
					{hostPath: filepath.Join(devRoot, "nvidia-caps-imex-channels", "channel1"), containerPath: filepath.Join(devRoot, "nvidia-caps-imex-channels", "channel1")},
					{hostPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap0"), containerPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap0")},
					{hostPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap1"), containerPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap1")},
				}
			},
		},
		{
			name: "symlinks to char devices resolve hostPath while preserving containerPath",
			fixture: fabricDevFixture{
				channels: channelFixture{symlinks: map[string]string{"channel0": "/dev/null"}},
				caps: map[string]capFixture{
					"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 15\n", nodeName: "nvidia-cap15", nodeTarget: "/dev/null"},
					"mncc-mgmt":        {procContent: "DeviceFileMinor: 21\n", nodeName: "nvidia-cap21", nodeTarget: "/dev/zero"},
				},
			},
			devStat: charDevStat,
			wantDevs: func(devRoot string) []gb300FabricDevice {
				return []gb300FabricDevice{
					{hostPath: "/dev/null", containerPath: filepath.Join(devRoot, "nvidia-caps-imex-channels", "channel0")},
					{hostPath: "/dev/null", containerPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap15")},
					{hostPath: "/dev/zero", containerPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap21")},
				}
			},
		},
		{
			name: "non-char and dangling channel entries are skipped without dropping valid channel",
			fixture: fabricDevFixture{
				channels: channelFixture{
					files:    []string{"channel2"},
					dirs:     []string{"channel0"},
					symlinks: map[string]string{"channel1": "nonexistent-target"},
				},
				caps: map[string]capFixture{
					"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 15\n", nodeName: "nvidia-cap15"},
					"mncc-mgmt":        {procContent: "DeviceFileMinor: 21\n", nodeName: "nvidia-cap21"},
				},
			},
			devStat: fakeDevStat,
			wantDevs: func(devRoot string) []gb300FabricDevice {
				return []gb300FabricDevice{
					{hostPath: filepath.Join(devRoot, "nvidia-caps-imex-channels", "channel2"), containerPath: filepath.Join(devRoot, "nvidia-caps-imex-channels", "channel2")},
					{hostPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap15"), containerPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap15")},
					{hostPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap21"), containerPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap21")},
				}
			},
			wantSkipped:    2,
			wantErrIs:      []error{fs.ErrNotExist},
			wantErrSubstrs: []string{"not a character device", "cannot resolve"},
		},
		{
			name: "missing channels dir and missing proc file both accumulate skips",
			fixture: fabricDevFixture{
				channels: channelFixture{missingDir: true},
				caps: map[string]capFixture{
					"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 15\n", nodeName: "nvidia-cap15"},
				},
			},
			devStat: fakeDevStat,
			wantDevs: func(devRoot string) []gb300FabricDevice {
				return []gb300FabricDevice{
					{hostPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap15"), containerPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap15")},
				}
			},
			wantSkipped:    2,
			wantErrIs:      []error{fs.ErrNotExist},
			wantErrSubstrs: []string{"cannot read", "mncc-mgmt"},
		},
		{
			name: "missing proc file is skipped with cannot read error",
			fixture: fabricDevFixture{
				caps: map[string]capFixture{
					"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 15\n", nodeName: "nvidia-cap15"},
				},
			},
			devStat: fakeDevStat,
			wantDevs: func(devRoot string) []gb300FabricDevice {
				return []gb300FabricDevice{
					{hostPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap15"), containerPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap15")},
				}
			},
			wantSkipped:    1,
			wantErrIs:      []error{fs.ErrNotExist},
			wantErrSubstrs: []string{"cannot read", "mncc-mgmt"},
		},
		{
			name: "charDevStat rejects regular files",
			fixture: fabricDevFixture{
				channels: channelFixture{files: []string{"channel0"}},
				caps: map[string]capFixture{
					"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 15\n", nodeName: "nvidia-cap15"},
				},
			},
			devStat:        charDevStat,
			wantSkipped:    3,
			wantErrIs:      []error{fs.ErrNotExist},
			wantErrSubstrs: []string{"not a character device", "cannot read"},
		},
		{
			name: "missing DeviceFileMinor line is skipped",
			fixture: fabricDevFixture{
				caps: map[string]capFixture{
					"fabric-imex-mgmt": {procContent: "DeviceFileMode: 292\n"},
					"mncc-mgmt":        {procContent: "DeviceFileMinor: 21\n", nodeName: "nvidia-cap21"},
				},
			},
			devStat: fakeDevStat,
			wantDevs: func(devRoot string) []gb300FabricDevice {
				return []gb300FabricDevice{
					{hostPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap21"), containerPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap21")},
				}
			},
			wantSkipped:    1,
			wantErrSubstrs: []string{"missing DeviceFileMinor"},
		},
		{
			name: "malformed DeviceFileMinor is skipped",
			fixture: fabricDevFixture{
				caps: map[string]capFixture{
					"fabric-imex-mgmt": {procContent: "DeviceFileMinor: not-a-number\n"},
					"mncc-mgmt":        {procContent: "DeviceFileMinor: -1\n"},
				},
			},
			devStat:        fakeDevStat,
			wantSkipped:    2,
			wantErrSubstrs: []string{"invalid DeviceFileMinor"},
		},
		{
			name: "duplicate and overflow DeviceFileMinor are skipped",
			fixture: fabricDevFixture{
				caps: map[string]capFixture{
					"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 15\nDeviceFileMinor: 16\n"},
					"mncc-mgmt":        {procContent: "DeviceFileMinor: 99999999999999999999999999\n"},
				},
			},
			devStat:        fakeDevStat,
			wantSkipped:    2,
			wantErrSubstrs: []string{"duplicate DeviceFileMinor", "invalid DeviceFileMinor"},
		},
		{
			name: "CRLF proc file parses DeviceFileMinor",
			fixture: fabricDevFixture{
				caps: map[string]capFixture{
					"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 15\r\nDeviceFileMode: 292\r\n", nodeName: "nvidia-cap15"},
					"mncc-mgmt":        {procContent: "DeviceFileMinor: 21\r\nDeviceFileMode: 292\r\n", nodeName: "nvidia-cap21"},
				},
			},
			devStat: fakeDevStat,
			wantDevs: func(devRoot string) []gb300FabricDevice {
				return []gb300FabricDevice{
					{hostPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap15"), containerPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap15")},
					{hostPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap21"), containerPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap21")},
				}
			},
		},
		{
			name: "missing cap device node is skipped",
			fixture: fabricDevFixture{
				caps: map[string]capFixture{
					"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 15\n"},
					"mncc-mgmt":        {procContent: "DeviceFileMinor: 21\n", nodeName: "nvidia-cap21"},
				},
			},
			devStat: fakeDevStat,
			wantDevs: func(devRoot string) []gb300FabricDevice {
				return []gb300FabricDevice{
					{hostPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap21"), containerPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap21")},
				}
			},
			wantSkipped: 1,
			wantErrIs:   []error{fs.ErrNotExist},
		},
		{
			name: "non-char cap device node is skipped",
			fixture: fabricDevFixture{
				caps: map[string]capFixture{
					"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 15\n", nodeName: "nvidia-cap15", nodeIsDir: true},
					"mncc-mgmt":        {procContent: "DeviceFileMinor: 21\n", nodeName: "nvidia-cap21"},
				},
			},
			devStat: fakeDevStat,
			wantDevs: func(devRoot string) []gb300FabricDevice {
				return []gb300FabricDevice{
					{hostPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap21"), containerPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap21")},
				}
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
			setupChannelFixture(t, devRoot, tc.fixture.channels)
			setupCapFixture(t, devRoot, procRoot, tc.fixture.caps, tc.fixture.extraCapNodes)

			gotDevs, gotSkipped := gb300FabricDevs(devRoot, procRoot, tc.devStat)
			var wantDevs []gb300FabricDevice
			if tc.wantDevs != nil {
				wantDevs = tc.wantDevs(devRoot)
			}
			if diff := cmp.Diff(wantDevs, gotDevs, cmp.AllowUnexported(gb300FabricDevice{})); diff != "" {
				t.Errorf("gb300FabricDevs() devs mismatch (-want +got):\n%s", diff)
			}
			if len(gotSkipped) != tc.wantSkipped {
				t.Fatalf("gb300FabricDevs() skipped %d (%v), want %d", len(gotSkipped), gotSkipped, tc.wantSkipped)
			}
			for _, target := range tc.wantErrIs {
				assertSkippedMatches(t, gotSkipped, func(err error) bool { return errors.Is(err, target) }, target.Error())
			}
			for _, substr := range tc.wantErrSubstrs {
				assertSkippedMatches(t, gotSkipped, func(err error) bool { return strings.Contains(err.Error(), substr) }, substr)
			}
		})
	}
}

func assertSkippedMatches(t *testing.T, errs []error, match func(error) bool, desc string) {
	t.Helper()
	for _, err := range errs {
		if match(err) {
			return
		}
	}
	t.Errorf("gb300FabricDevs() skip errors %v missing match for %q", errs, desc)
}

// oracleParseNvidiaCapMinor is an independent reference parser for
// /proc/driver/nvidia/capabilities/<name> files used by FuzzParseNvidiaCapMinor.
func oracleParseNvidiaCapMinor(data []byte) (int, bool) {
	found := false
	want := 0
	for _, rawLine := range bytes.Split(data, []byte("\n")) {
		trimmed := strings.TrimFunc(string(rawLine), unicode.IsSpace)
		const prefix = "DeviceFileMinor:"
		if !strings.HasPrefix(trimmed, prefix) {
			continue
		}
		if found {
			return 0, false
		}
		found = true
		rest := strings.TrimFunc(trimmed[len(prefix):], unicode.IsSpace)
		if rest == "" {
			return 0, false
		}
		for i := 0; i < len(rest); i++ {
			if rest[i] < '0' || rest[i] > '9' {
				return 0, false
			}
		}
		n, err := strconv.ParseUint(rest, 10, strconv.IntSize-1)
		if err != nil {
			return 0, false
		}
		want = int(n)
	}
	if !found {
		return 0, false
	}
	return want, true
}

func FuzzParseNvidiaCapMinor(f *testing.F) {
	seeds := [][]byte{
		[]byte("DeviceFileMinor: 15\nDeviceFileMode: 292\nDeviceFileModify: 0\n"),
		[]byte("DeviceFileMinor: 0\n"),
		[]byte("DeviceFileMinor: 9\n"),
		[]byte("  \t DeviceFileMinor:   \t 42 \t \n"),
		[]byte("DeviceFileMinor: -1\n"),
		[]byte("DeviceFileMinor: -0\n"),
		[]byte("DeviceFileMinor: +5\n"),
		[]byte("DeviceFileMinor: 99999999999999999999999999\n"),
		[]byte("DeviceFileMode: 292\nDeviceFileModify: 0\n"),
		[]byte("DeviceFileMinor: 15\nDeviceFileMinor: 21\n"),
		[]byte("DeviceFileMinor: 15\r\nDeviceFileMode: 292\r\n"),
		[]byte(""),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := parseNvidiaCapMinor(data)
		want, wantOK := oracleParseNvidiaCapMinor(data)
		if (err == nil) != wantOK {
			t.Fatalf("parseNvidiaCapMinor(%q) err=%v, oracle ok=%v", data, err, wantOK)
		}
		if err == nil {
			if got < 0 {
				t.Fatalf("parseNvidiaCapMinor(%q) = %d, must be non-negative", data, got)
			}
			if got != want {
				t.Fatalf("parseNvidiaCapMinor(%q) = %d, oracle = %d", data, got, want)
			}
		}
	})
}
