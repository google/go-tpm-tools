package launcher

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
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
