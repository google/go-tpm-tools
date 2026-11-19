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

	"github.com/containerd/containerd/oci"
	"github.com/google/go-tpm-tools/launcher/internal/logging"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

const (
	// gb300FabricContainerBinDir holds the IMEX and MNCCD binaries inside the
	// workload container. It is separate from /usr/local/nvidia/bin because
	// that directory is a bind mount of the read-only host driver bin
	// directory, where runc cannot create mount points.
	gb300FabricContainerBinDir = "/usr/local/nvidia/fabric/bin"

	defaultDevRoot  = "/dev"
	defaultProcRoot = "/proc"
)

// gb300FabricDevice is a host character device node to pass into the workload
// container for NVIDIA IMEX or MNCCD.
type gb300FabricDevice struct {
	// hostPath is the symlink-resolved host character device node passed to
	// oci.WithDevices, which lstats the source path.
	hostPath string
	// containerPath is where the device node appears inside the container.
	containerPath string
}

type gb300FabricConfig struct {
	binaries []string
	devRoot  string
	procRoot string
	stat     func(string) (os.FileInfo, error)
	devStat  func(string) (bool, uint64, error)
}

var (
	// gb300FabricBinaries are the IMEX and MNCCD binaries on GB300 images. They
	// are mounted read-only so the workload can run or query IMEX/MNCCD with
	// its own configs.
	gb300FabricBinaries = []string{
		"/usr/bin/nvidia-imex",
		"/usr/bin/nvidia-imex-ctl",
		"/usr/share/oem/nvidia-mnccd/rootfs/usr/bin/nvidia-mnccd",
	}

	// gb300FabricCapNames are the NVIDIA driver capability entries in
	// /proc/driver/nvidia/capabilities/ needed by nvidia-imex and nvidia-mnccd.
	gb300FabricCapNames = []string{
		"fabric-imex-mgmt",
		"mncc-mgmt",
	}

	imexChannelNameRegexp = regexp.MustCompile(`^channel\d+$`)

	defaultGB300FabricConfig = gb300FabricConfig{
		binaries: gb300FabricBinaries,
		devRoot:  defaultDevRoot,
		procRoot: defaultProcRoot,
		stat:     os.Stat,
		devStat:  charDevStat,
	}

	// findGB300FabricSpecOpts returns the OCI spec options for GB300 IMEX/MNCCD
	// mounts and devices. It is overridden in unit tests to keep
	// createOCISpecOpts hermetic.
	findGB300FabricSpecOpts = func(nonroot bool, logger logging.Logger) []oci.SpecOpts {
		return gb300FabricSpecOpts(defaultGB300FabricConfig, nonroot, logger)
	}
)

// gb300FabricSpecOpts builds OCI spec options for the GB300 IMEX and MNCCD
// binary mounts and device nodes. Missing or invalid paths are logged and
// skipped without failing the launch. For non-root containers, /dev/nvidia-caps
// capability nodes are skipped because bind-mounting 0400 root:root nodes in a
// user namespace yields EACCES.
func gb300FabricSpecOpts(cfg gb300FabricConfig, nonroot bool, logger logging.Logger) []oci.SpecOpts {
	var opts []oci.SpecOpts

	fabricMounts, skippedMounts := gb300FabricMounts(cfg.binaries, cfg.stat)
	for _, err := range skippedMounts {
		logger.Error(fmt.Sprintf("GB300 CC mode: skipping IMEX/MNCCD mount: %v", err))
	}
	for _, m := range fabricMounts {
		logger.Info(fmt.Sprintf("GB300 CC mode: mounting %s at %s", m.Source, m.Destination))
	}
	if len(fabricMounts) > 0 {
		opts = append(opts, oci.WithMounts(fabricMounts))
	}

	fabricDevs, skippedDevs := gb300IMEXChannelDevs(cfg.devRoot, cfg.devStat)
	if nonroot {
		// Capability device nodes are created 0400 root:root (driver DeviceFileMode 256).
		// In a user namespace, runc bind-mounts the host node, so open() fails with
		// EACCES for every container user. Keep passing the 0666 IMEX channels and
		// binary mounts.
		logger.Error("GB300 CC mode: IMEX/MNCCD capability device passthrough is not supported for non-root containers; skipping /dev/nvidia-caps nodes")
	} else {
		capDevs, skippedCaps := gb300CapDevs(cfg.devRoot, cfg.procRoot, cfg.devStat)
		fabricDevs = append(fabricDevs, capDevs...)
		skippedDevs = append(skippedDevs, skippedCaps...)
	}
	for _, err := range skippedDevs {
		logger.Error(fmt.Sprintf("GB300 CC mode: skipping IMEX/MNCCD device: %v", err))
	}
	for _, dev := range fabricDevs {
		logger.Info(fmt.Sprintf("GB300 CC mode: passing IMEX/MNCCD device %s as %s", dev.hostPath, dev.containerPath))
		opts = append(opts, oci.WithDevices(dev.hostPath, dev.containerPath, "rwm"))
	}

	return opts
}

// gb300FabricMounts returns a read-only bind mount into
// gb300FabricContainerBinDir for each regular file in binaries that exists on
// the host, using stat to follow symlinks. For each skipped path, it returns an
// error describing why the path was skipped.
func gb300FabricMounts(binaries []string, stat func(string) (os.FileInfo, error)) ([]specs.Mount, []error) {
	var mounts []specs.Mount
	var skipped []error
	for _, hostPath := range binaries {
		fi, err := stat(hostPath)
		if err != nil {
			skipped = append(skipped, fmt.Errorf("cannot stat %q: %w", hostPath, err))
			continue
		}
		if !fi.Mode().IsRegular() {
			skipped = append(skipped, fmt.Errorf("%q is not a regular file (mode %v)", hostPath, fi.Mode()))
			continue
		}
		mounts = append(mounts, specs.Mount{
			Type:        "bind",
			Source:      hostPath,
			Destination: path.Join(gb300FabricContainerBinDir, path.Base(hostPath)),
			Options:     []string{"bind", "ro"},
		})
	}
	return mounts, skipped
}

func resolveGB300CharDevice(devPath string, devStat func(string) (bool, uint64, error)) (gb300FabricDevice, error) {
	resolved, err := filepath.EvalSymlinks(devPath)
	if err != nil {
		return gb300FabricDevice{}, fmt.Errorf("cannot resolve %q: %w", devPath, err)
	}
	isChar, _, err := devStat(resolved)
	if err != nil {
		return gb300FabricDevice{}, fmt.Errorf("cannot stat %q: %w", resolved, err)
	}
	if !isChar {
		return gb300FabricDevice{}, fmt.Errorf("%q is not a character device", resolved)
	}
	return gb300FabricDevice{
		hostPath:      resolved,
		containerPath: devPath,
	}, nil
}

// gb300IMEXChannelDevs discovers the host IMEX channel character devices under
// <devRoot>/nvidia-caps-imex-channels/channel<N>. Symlinks are resolved so
// hostPath holds the real device node for oci.WithDevices while containerPath
// keeps the discovered path. For each missing or invalid directory or node, it
// returns an error describing why it was skipped.
func gb300IMEXChannelDevs(devRoot string, devStat func(string) (bool, uint64, error)) ([]gb300FabricDevice, []error) {
	chanDir := filepath.Join(devRoot, "nvidia-caps-imex-channels")
	entries, err := os.ReadDir(chanDir)
	if err != nil {
		return nil, []error{fmt.Errorf("cannot read %q: %w", chanDir, err)}
	}
	var devs []gb300FabricDevice
	var skipped []error
	for _, entry := range entries {
		if !imexChannelNameRegexp.MatchString(entry.Name()) {
			continue
		}
		devPath := filepath.Join(chanDir, entry.Name())
		dev, err := resolveGB300CharDevice(devPath, devStat)
		if err != nil {
			skipped = append(skipped, err)
			continue
		}
		devs = append(devs, dev)
	}
	return devs, skipped
}

// gb300CapDevs discovers the NVIDIA capability character devices for
// fabric-imex-mgmt and mncc-mgmt under <devRoot>/nvidia-caps/ using minors
// from <procRoot>/driver/nvidia/capabilities/<name>. Symlinks are resolved so
// hostPath holds the real device node for oci.WithDevices while containerPath
// keeps the discovered path. For each missing or invalid proc file or node, it
// returns an error describing why it was skipped.
func gb300CapDevs(devRoot, procRoot string, devStat func(string) (bool, uint64, error)) ([]gb300FabricDevice, []error) {
	var devs []gb300FabricDevice
	var skipped []error
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
		dev, err := resolveGB300CharDevice(devPath, devStat)
		if err != nil {
			skipped = append(skipped, fmt.Errorf("capability %q: %w", procPath, err))
			continue
		}
		devs = append(devs, dev)
	}
	return devs, skipped
}

// parseNvidiaCapMinor parses the "DeviceFileMinor: <N>" line from an NVIDIA
// driver /proc/driver/nvidia/capabilities/<name> file.
func parseNvidiaCapMinor(data []byte) (int, error) {
	found := false
	minor := 0
	for _, line := range strings.Split(string(data), "\n") {
		val, ok := strings.CutPrefix(strings.TrimSpace(line), "DeviceFileMinor:")
		if !ok {
			continue
		}
		if found {
			return 0, errors.New("duplicate DeviceFileMinor")
		}
		found = true
		val = strings.TrimSpace(val)
		n, err := strconv.ParseUint(val, 10, strconv.IntSize-1)
		if err != nil {
			return 0, fmt.Errorf("invalid DeviceFileMinor %q: %w", val, err)
		}
		minor = int(n)
	}
	if !found {
		return 0, errors.New("missing DeviceFileMinor")
	}
	return minor, nil
}
