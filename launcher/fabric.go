package launcher

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

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

	defaultDevRoot  = "/dev"
	defaultProcRoot = "/proc"
)

// gb300FabricPath describes a host file or directory of the NVIDIA IMEX or
// MNCCD daemon to bind-mount read-only into the workload container.
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

	// gb300FabricCapNames are the NVIDIA driver capability entries in
	// /proc/driver/nvidia/capabilities/ needed by nvidia-imex and nvidia-mnccd.
	gb300FabricCapNames = []string{
		"fabric-imex-mgmt",
		"mncc-mgmt",
	}

	imexChannelNameRegexp = regexp.MustCompile(`^channel\d+$`)

	// findGB300FabricMounts returns the IMEX and MNCCD mounts for the workload
	// container. It is overridden in unit tests to keep createOCISpecOpts
	// hermetic.
	findGB300FabricMounts = func() ([]specs.Mount, []error) {
		return gb300FabricMounts(gb300FabricPaths, os.Stat)
	}

	// findGB300FabricDevs returns the IMEX channel and fabric capability device
	// nodes for the workload container. It is overridden in unit tests to keep
	// createOCISpecOpts hermetic.
	findGB300FabricDevs = func() ([]string, []error) {
		return gb300FabricDevs(defaultDevRoot, defaultProcRoot, charDevStat)
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

// gb300FabricDevs discovers the host IMEX channel devices under
// <devRoot>/nvidia-caps-imex-channels/channel<N> and the NVIDIA capability
// devices for fabric-imex-mgmt and mncc-mgmt under <devRoot>/nvidia-caps/ using
// minors from <procRoot>/driver/nvidia/capabilities/<name>.
//
// devStat follows symlinks and reports whether a path is a character device and
// its device number. When devStat is nil, charDevStat is used. For each missing
// or invalid channel directory, proc file, or device node, it returns an error
// describing why it was skipped.
func gb300FabricDevs(devRoot, procRoot string, devStat func(string) (bool, uint64, error)) ([]string, []error) {
	if devStat == nil {
		devStat = charDevStat
	}

	var devs []string
	var skipped []error

	chanDir := filepath.Join(devRoot, "nvidia-caps-imex-channels")
	entries, err := os.ReadDir(chanDir)
	if err != nil {
		skipped = append(skipped, fmt.Errorf("cannot read %q: %w", chanDir, err))
	} else {
		for _, entry := range entries {
			if !imexChannelNameRegexp.MatchString(entry.Name()) {
				continue
			}
			devPath := filepath.Join(chanDir, entry.Name())
			isChar, _, err := devStat(devPath)
			if err != nil {
				skipped = append(skipped, fmt.Errorf("cannot stat %q: %w", devPath, err))
				continue
			}
			if !isChar {
				skipped = append(skipped, fmt.Errorf("%q is not a character device", devPath))
				continue
			}
			devs = append(devs, devPath)
		}
	}

	for _, capName := range gb300FabricCapNames {
		procPath := filepath.Join(procRoot, "driver", "nvidia", "capabilities", capName)
		data, err := os.ReadFile(procPath)
		if err != nil {
			skipped = append(skipped, fmt.Errorf("cannot read %q: %w", procPath, err))
			continue
		}
		minor, err := parseNvidiaCapMinor(data)
		if err != nil {
			skipped = append(skipped, fmt.Errorf("cannot parse %q: %w", procPath, err))
			continue
		}
		devPath := filepath.Join(devRoot, "nvidia-caps", fmt.Sprintf("nvidia-cap%d", minor))
		isChar, _, err := devStat(devPath)
		if err != nil {
			skipped = append(skipped, fmt.Errorf("cannot stat %q (from %q): %w", devPath, procPath, err))
			continue
		}
		if !isChar {
			skipped = append(skipped, fmt.Errorf("%q is not a character device (from %q)", devPath, procPath))
			continue
		}
		devs = append(devs, devPath)
	}

	return devs, skipped
}

// parseNvidiaCapMinor parses the "DeviceFileMinor: <N>" line from an NVIDIA
// driver /proc/driver/nvidia/capabilities/<name> file.
func parseNvidiaCapMinor(data []byte) (int, error) {
	for _, line := range strings.Split(string(data), "\n") {
		val, ok := strings.CutPrefix(strings.TrimSpace(line), "DeviceFileMinor:")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		minor, err := strconv.Atoi(val)
		if err != nil || minor < 0 {
			return 0, fmt.Errorf("invalid DeviceFileMinor %q", val)
		}
		return minor, nil
	}
	return 0, errors.New("missing DeviceFileMinor")
}
