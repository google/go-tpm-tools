package launcher

import (
	"fmt"
	"os"
	"path"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

const (
	// gb300FabricContainerDir is the workload container directory that holds the
	// NVIDIA IMEX and MNCCD binaries and configs. It is separate from
	// /usr/local/nvidia/bin because that directory is a bind mount of the
	// read-only host driver bin directory, where runc cannot create mount points.
	gb300FabricContainerDir = "/usr/local/nvidia/fabric"
	// gb300FabricContainerBinDir holds the IMEX and MNCCD binaries.
	gb300FabricContainerBinDir = gb300FabricContainerDir + "/bin"
	// gb300FabricContainerEtcDir holds the IMEX and MNCCD config directories.
	gb300FabricContainerEtcDir = gb300FabricContainerDir + "/etc"
)

// gb300FabricPath is a host file or directory of the NVIDIA IMEX or MNCCD
// daemon that is bind-mounted read-only into the workload container.
type gb300FabricPath struct {
	hostPath      string
	containerPath string
	// isDir is true if hostPath must be a directory and false if it must be a
	// regular file.
	isDir bool
}

var (
	// gb300FabricPaths are the IMEX and MNCCD binaries and configs on GB300
	// images. The image starts and owns both daemons. These mounts let the
	// workload see how the daemons are configured and talk to them, for example
	// with `nvidia-imex-ctl -c /usr/local/nvidia/fabric/etc/nvidia-imex/config.cfg -N`.
	gb300FabricPaths = []gb300FabricPath{
		{hostPath: "/usr/bin/nvidia-imex", containerPath: path.Join(gb300FabricContainerBinDir, "nvidia-imex")},
		{hostPath: "/usr/bin/nvidia-imex-ctl", containerPath: path.Join(gb300FabricContainerBinDir, "nvidia-imex-ctl")},
		{hostPath: "/usr/share/oem/nvidia-mnccd/rootfs/usr/bin/nvidia-mnccd", containerPath: path.Join(gb300FabricContainerBinDir, "nvidia-mnccd")},
		{hostPath: "/usr/share/oem/nvidia-imex/etc", containerPath: path.Join(gb300FabricContainerEtcDir, "nvidia-imex"), isDir: true},
		{hostPath: "/usr/share/oem/nvidia-mnccd/etc", containerPath: path.Join(gb300FabricContainerEtcDir, "nvidia-mnccd"), isDir: true},
	}

	// findGB300FabricMounts returns the IMEX and MNCCD mounts for the workload
	// container. It is overridden in unit tests to keep createOCISpecOpts
	// hermetic.
	findGB300FabricMounts = func() ([]specs.Mount, []error) {
		return gb300FabricMounts(gb300FabricPaths, os.Stat)
	}
)

// gb300FabricMounts returns a read-only bind mount for each path that exists on
// the host with the expected type, using stat to follow symlinks. When stat is
// nil, os.Stat is used. For each skipped path, it returns an error describing
// why the path was skipped.
func gb300FabricMounts(paths []gb300FabricPath, stat func(string) (os.FileInfo, error)) ([]specs.Mount, []error) {
	if stat == nil {
		stat = os.Stat
	}
	var mounts []specs.Mount
	var skipped []error
	for _, p := range paths {
		fi, err := stat(p.hostPath)
		if err != nil {
			skipped = append(skipped, fmt.Errorf("cannot stat %q: %w", p.hostPath, err))
			continue
		}
		bindOpt := "bind"
		if p.isDir {
			if !fi.IsDir() {
				skipped = append(skipped, fmt.Errorf("%q is not a directory (mode %v)", p.hostPath, fi.Mode()))
				continue
			}
			bindOpt = "rbind"
		} else if !fi.Mode().IsRegular() {
			skipped = append(skipped, fmt.Errorf("%q is not a regular file (mode %v)", p.hostPath, fi.Mode()))
			continue
		}
		mounts = append(mounts, specs.Mount{
			Type:        "bind",
			Source:      p.hostPath,
			Destination: p.containerPath,
			Options:     []string{bindOpt, "ro"},
		})
	}
	return mounts, skipped
}
