package launcher

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/oci"
	"github.com/google/go-cmp/cmp"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

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
	subdir := filepath.Join(dir, "dir")
	if err := os.Mkdir(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "nvidia-imex-ctl")

	mount := func(src, dst string) specs.Mount {
		return specs.Mount{Type: "bind", Source: src, Destination: dst, Options: []string{"bind", "ro"}}
	}

	tests := []struct {
		name          string
		binaries      []string
		wantMounts    []specs.Mount
		wantSkipped   int
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
			wantSkipped: 1,
			wantErrIs:   fs.ErrNotExist,
		},
		{
			name:          "directory where a regular file is expected is skipped",
			binaries:      []string{subdir},
			wantSkipped:   1,
			wantErrSubstr: "not a regular file",
		},
		{
			name:        "skipped path does not drop the others",
			binaries:    []string{regular, missing, second},
			wantMounts:  []specs.Mount{mount(regular, "/usr/local/nvidia/fabric/bin/nvidia-imex"), mount(second, "/usr/local/nvidia/fabric/bin/nvidia-mnccd")},
			wantSkipped: 1,
			wantErrIs:   fs.ErrNotExist,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotMounts, gotSkipped := gb300FabricMounts(tc.binaries, os.Stat)
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
		wantPaths      []string
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
			devStat:   fakeDevStat,
			wantPaths: []string{"nvidia-caps/nvidia-cap15", "nvidia-caps/nvidia-cap21"},
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
			devStat:   fakeDevStat,
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
			devStat:   fakeDevStat,
			wantPaths: []string{"nvidia-caps-imex-channels/channel0", "nvidia-caps-imex-channels/channel1", "nvidia-caps/nvidia-cap0", "nvidia-caps/nvidia-cap1"},
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
			devStat:        fakeDevStat,
			wantPaths:      []string{"nvidia-caps-imex-channels/channel2", "nvidia-caps/nvidia-cap15", "nvidia-caps/nvidia-cap21"},
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
			devStat:        fakeDevStat,
			wantPaths:      []string{"nvidia-caps/nvidia-cap15"},
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
			devStat:        fakeDevStat,
			wantPaths:      []string{"nvidia-caps/nvidia-cap15"},
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
			devStat:        fakeDevStat,
			wantPaths:      []string{"nvidia-caps/nvidia-cap21"},
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
			devStat:   fakeDevStat,
			wantPaths: []string{"nvidia-caps/nvidia-cap15", "nvidia-caps/nvidia-cap21"},
		},
		{
			name: "missing cap device node is skipped",
			fixture: fabricDevFixture{
				caps: map[string]capFixture{
					"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 15\n"},
					"mncc-mgmt":        {procContent: "DeviceFileMinor: 21\n", nodeName: "nvidia-cap21"},
				},
			},
			devStat:     fakeDevStat,
			wantPaths:   []string{"nvidia-caps/nvidia-cap21"},
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
			devStat:        fakeDevStat,
			wantPaths:      []string{"nvidia-caps/nvidia-cap21"},
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

			gotDevs, gotSkipped := gb300IMEXChannelDevs(devRoot, tc.devStat)
			capDevs, capSkipped := gb300CapDevs(devRoot, procRoot, tc.devStat)
			gotDevs = append(gotDevs, capDevs...)
			gotSkipped = append(gotSkipped, capSkipped...)

			var wantDevs []gb300FabricDevice
			for _, rel := range tc.wantPaths {
				p := filepath.Join(devRoot, rel)
				wantDevs = append(wantDevs, gb300FabricDevice{hostPath: p, containerPath: p})
			}
			if diff := cmp.Diff(wantDevs, gotDevs, cmp.AllowUnexported(gb300FabricDevice{})); diff != "" {
				t.Errorf("fabric devs mismatch (-want +got):\n%s", diff)
			}
			if len(gotSkipped) != tc.wantSkipped {
				t.Fatalf("fabric devs skipped %d (%v), want %d", len(gotSkipped), gotSkipped, tc.wantSkipped)
			}
			assertSkippedErrors(t, gotSkipped, tc.wantErrIs, tc.wantErrSubstrs)
		})
	}
}

func assertSkippedErrors(t *testing.T, got []error, wantIs []error, wantSubstrs []string) {
	t.Helper()
	for _, target := range wantIs {
		if !slices.ContainsFunc(got, func(err error) bool { return errors.Is(err, target) }) {
			t.Errorf("skip errors %v missing error wrapping %v", got, target)
		}
	}
	for _, substr := range wantSubstrs {
		if !slices.ContainsFunc(got, func(err error) bool { return strings.Contains(err.Error(), substr) }) {
			t.Errorf("skip errors %v missing substring %q", got, substr)
		}
	}
}

func TestGB300FabricDevs_Symlink(t *testing.T) {
	root := t.TempDir()
	devRoot := filepath.Join(root, "dev")
	procRoot := filepath.Join(root, "proc")
	setupChannelFixture(t, devRoot, channelFixture{symlinks: map[string]string{"channel0": "/dev/null"}})
	setupCapFixture(t, devRoot, procRoot, map[string]capFixture{
		"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 15\n", nodeName: "nvidia-cap15", nodeTarget: "/dev/null"},
		"mncc-mgmt":        {procContent: "DeviceFileMinor: 21\n", nodeName: "nvidia-cap21", nodeTarget: "/dev/zero"},
	}, nil)

	gotDevs, gotSkipped := gb300IMEXChannelDevs(devRoot, charDevStat)
	capDevs, capSkipped := gb300CapDevs(devRoot, procRoot, charDevStat)
	gotDevs = append(gotDevs, capDevs...)
	gotSkipped = append(gotSkipped, capSkipped...)

	if len(gotSkipped) != 0 {
		t.Fatalf("unexpected skipped errors: %v", gotSkipped)
	}
	wantDevs := []gb300FabricDevice{
		{hostPath: "/dev/null", containerPath: filepath.Join(devRoot, "nvidia-caps-imex-channels", "channel0")},
		{hostPath: "/dev/null", containerPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap15")},
		{hostPath: "/dev/zero", containerPath: filepath.Join(devRoot, "nvidia-caps", "nvidia-cap21")},
	}
	if diff := cmp.Diff(wantDevs, gotDevs, cmp.AllowUnexported(gb300FabricDevice{})); diff != "" {
		t.Errorf("symlink devs mismatch (-want +got):\n%s", diff)
	}
}

func setupFabricSpecFixture(t *testing.T, presentBins []string, missingBin string, chanFx channelFixture, caps map[string]capFixture) gb300FabricConfig {
	t.Helper()
	root := t.TempDir()
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
	setupCapFixture(t, devRoot, procRoot, caps, nil)
	return gb300FabricConfig{
		binaries: binaries,
		devRoot:  devRoot,
		procRoot: procRoot,
		stat:     os.Stat,
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
		"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 15\n", nodeName: "nvidia-cap15", nodeTarget: "/dev/zero"},
		"mncc-mgmt":        {procContent: "DeviceFileMinor: 21\n", nodeName: "nvidia-cap21", nodeTarget: "/dev/null"},
	}

	t.Run("root_mounts_all_binaries_channels_and_caps", func(t *testing.T) {
		cfg := setupFabricSpecFixture(t, allBins, "", channelFixture{symlinks: map[string]string{"channel0": "/dev/null"}}, allCaps)
		logger := &fakeLogger{}
		gotSpec, err := applySpecOptsToSpec(ctx, append([]oci.SpecOpts{nil}, gb300FabricSpecOpts(cfg, false, logger)...))
		if err != nil {
			t.Fatalf("applySpecOptsToSpec() failed: %v", err)
		}
		if len(logger.errors) != 0 {
			t.Errorf("unexpected error logs: %v", logger.errors)
		}
		assertFabricBinMountsInSpec(t, gotSpec, filepath.Dir(cfg.binaries[0]), allBins)
		assertCharDeviceInSpec(t, gotSpec, "/dev/null", filepath.Join(cfg.devRoot, "nvidia-caps-imex-channels", "channel0"), "rwm")
		assertCharDeviceInSpec(t, gotSpec, "/dev/zero", filepath.Join(cfg.devRoot, "nvidia-caps", "nvidia-cap15"), "rwm")
		assertCharDeviceInSpec(t, gotSpec, "/dev/null", filepath.Join(cfg.devRoot, "nvidia-caps", "nvidia-cap21"), "rwm")
		assertSubstrInLogs(t, logger.logs, []string{
			"GB300 CC mode: mounting " + cfg.binaries[0] + " at /usr/local/nvidia/fabric/bin/nvidia-imex",
			"GB300 CC mode: passing IMEX/MNCCD device /dev/null as " + filepath.Join(cfg.devRoot, "nvidia-caps-imex-channels", "channel0"),
			"GB300 CC mode: passing IMEX/MNCCD device /dev/zero as " + filepath.Join(cfg.devRoot, "nvidia-caps", "nvidia-cap15"),
		})
	})

	t.Run("nonroot_skips_caps_keeps_binaries_and_channels", func(t *testing.T) {
		cfg := setupFabricSpecFixture(t, allBins, "", channelFixture{symlinks: map[string]string{"channel0": "/dev/null"}}, allCaps)
		logger := &fakeLogger{}
		gotSpec, err := applySpecOptsToSpec(ctx, append([]oci.SpecOpts{nil}, gb300FabricSpecOpts(cfg, true, logger)...))
		if err != nil {
			t.Fatalf("applySpecOptsToSpec() failed: %v", err)
		}
		assertFabricBinMountsInSpec(t, gotSpec, filepath.Dir(cfg.binaries[0]), allBins)
		assertCharDeviceInSpec(t, gotSpec, "/dev/null", filepath.Join(cfg.devRoot, "nvidia-caps-imex-channels", "channel0"), "rwm")
		assertDeviceAbsentInSpec(t, gotSpec, filepath.Join(cfg.devRoot, "nvidia-caps", "nvidia-cap15"))
		assertDeviceAbsentInSpec(t, gotSpec, filepath.Join(cfg.devRoot, "nvidia-caps", "nvidia-cap21"))
		assertSubstrInLogs(t, logger.errors, []string{
			"GB300 CC mode: IMEX/MNCCD capability device passthrough is not supported for non-root containers; skipping /dev/nvidia-caps nodes",
		})
	})

	t.Run("missing_mount_channel_and_cap_log_errors_without_failing", func(t *testing.T) {
		cfg := setupFabricSpecFixture(t, []string{"nvidia-imex"}, "nvidia-imex-ctl", channelFixture{missingDir: true}, map[string]capFixture{
			"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 15\n", nodeName: "nvidia-cap15", nodeTarget: "/dev/zero"},
		})
		logger := &fakeLogger{}
		gotSpec, err := applySpecOptsToSpec(ctx, append([]oci.SpecOpts{nil}, gb300FabricSpecOpts(cfg, false, logger)...))
		if err != nil {
			t.Fatalf("applySpecOptsToSpec() failed: %v", err)
		}
		assertCharDeviceInSpec(t, gotSpec, "/dev/zero", filepath.Join(cfg.devRoot, "nvidia-caps", "nvidia-cap15"), "rwm")
		assertSubstrInLogs(t, logger.errors, []string{
			"GB300 CC mode: skipping IMEX/MNCCD mount:",
			"GB300 CC mode: skipping IMEX/MNCCD device: cannot read",
			"nvidia-caps-imex-channels",
			"mncc-mgmt",
		})
	})
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
		[]byte("DeviceFileMinor: 0x10\n"),
		[]byte("DeviceFileMinor: 1_0\n"),
		[]byte("DeviceFileMinor: " + strconv.FormatInt(math.MaxInt, 10) + "\n"),
		[]byte("DeviceFileMinor: " + strconv.FormatUint(uint64(math.MaxInt)+1, 10) + "\n"),
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
