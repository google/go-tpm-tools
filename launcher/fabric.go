package launcher

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/containerd/containerd/oci"
	"github.com/google/go-tpm-tools/launcher/internal/logging"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

const (
	// gb300FabricContainerBinDir holds the IMEX and MNCCD binaries inside the
	// workload container. It is separate from /usr/local/nvidia/bin because
	// that directory is a bind mount of the read-only host driver bin
	// directory, where runc cannot create mount points.
	gb300FabricContainerBinDir = "/usr/local/nvidia/fabric/bin"

	defaultDevRoot  = "/dev"
	defaultProcRoot = "/proc"

	imexChannelDriverName = "nvidia-caps-imex-channels"
	nvidiaCapsDriverName  = "nvidia-caps"
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

	imexChannelNameRegexp = regexp.MustCompile(`^channel(\d+)$`)

	defaultGB300FabricConfig = gb300FabricConfig{
		binaries: gb300FabricBinaries,
		devRoot:  defaultDevRoot,
		procRoot: defaultProcRoot,
		devStat:  charDevStat,
	}

	// findGB300FabricSpecOpts returns the OCI spec options for GB300 IMEX/MNCCD
	// mounts and devices. It is overridden in unit tests to keep
	// createOCISpecOpts hermetic.
	findGB300FabricSpecOpts = func(nonroot bool, logger logging.Logger) ([]oci.SpecOpts, error) {
		return gb300FabricSpecOpts(defaultGB300FabricConfig, nonroot, logger)
	}
)

// gb300FabricSpecOpts builds OCI spec options for the GB300 IMEX and MNCCD
// binary mounts and device nodes. Absent paths (fs.ErrNotExist) are logged and
// skipped; unexpected filesystem, parsing, device-type, or major/minor errors
// fail closed. For non-root containers, /dev/nvidia-caps capability nodes are
// skipped because bind-mounting 0400 root:root nodes in a user namespace yields
// EACCES.
func gb300FabricSpecOpts(cfg gb300FabricConfig, nonroot bool, logger logging.Logger) ([]oci.SpecOpts, error) {
	var opts []oci.SpecOpts

	fabricMounts, skippedMounts, err := gb300FabricMounts(cfg.binaries)
	if err != nil {
		return nil, err
	}
	for _, err := range skippedMounts {
		logger.Error(fmt.Sprintf("GB300 CC mode: skipping IMEX/MNCCD mount: %v", err))
	}
	for _, m := range fabricMounts {
		logger.Info(fmt.Sprintf("GB300 CC mode: mounting %s at %s", m.Source, m.Destination))
	}
	if len(fabricMounts) > 0 {
		opts = append(opts, oci.WithMounts(fabricMounts))
	}

	fabricDevs, skippedDevs, err := gb300IMEXChannelDevs(cfg.devRoot, cfg.procRoot, cfg.devStat)
	if err != nil {
		return nil, err
	}
	if nonroot {
		// Capability device nodes are created 0400 root:root (driver DeviceFileMode 256).
		// In a user namespace, runc bind-mounts the host node, so open() fails with
		// EACCES for every container user. Keep passing the 0666 IMEX channels and
		// binary mounts.
		logger.Error("GB300 CC mode: IMEX/MNCCD capability device passthrough is not supported for non-root containers; skipping /dev/nvidia-caps nodes")
	} else {
		capDevs, skippedCaps, err := gb300CapDevs(cfg.devRoot, cfg.procRoot, cfg.devStat)
		if err != nil {
			return nil, err
		}
		fabricDevs = append(fabricDevs, capDevs...)
		skippedDevs = append(skippedDevs, skippedCaps...)
	}
	for _, err := range skippedDevs {
		logger.Error(fmt.Sprintf("GB300 CC mode: skipping IMEX/MNCCD device: %v", err))
	}
	for _, dev := range fabricDevs {
		logger.Info(fmt.Sprintf("GB300 CC mode: passing IMEX/MNCCD device %s as %s", dev.hostPath, dev.containerPath))
		opts = append(opts, oci.WithDevices(dev.hostPath, dev.containerPath, "rw"))
	}

	return opts, nil
}

// gb300FabricMounts returns a read-only bind mount into
// gb300FabricContainerBinDir for each regular file in binaries that exists on
// the host, following symlinks. Missing paths (fs.ErrNotExist on lstat) are
// returned as skipped errors; dangling symlinks, non-regular files, and other
// stat errors fail closed.
func gb300FabricMounts(binaries []string) ([]specs.Mount, []error, error) {
	var mounts []specs.Mount
	var skipped []error
	for _, hostPath := range binaries {
		if _, err := os.Lstat(hostPath); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				skipped = append(skipped, fmt.Errorf("cannot stat %q: %w", hostPath, err))
				continue
			}
			return nil, nil, fmt.Errorf("cannot lstat %q: %w", hostPath, err)
		}
		fi, err := os.Stat(hostPath)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot stat %q: %w", hostPath, err)
		}
		if !fi.Mode().IsRegular() {
			return nil, nil, fmt.Errorf("%q is not a regular file (mode %v)", hostPath, fi.Mode())
		}
		mounts = append(mounts, specs.Mount{
			Type:        "bind",
			Source:      hostPath,
			Destination: path.Join(gb300FabricContainerBinDir, path.Base(hostPath)),
			Options:     []string{"bind", "ro"},
		})
	}
	return mounts, skipped, nil
}

func resolveGB300CharDevice(devPath string, wantMajor, wantMinor uint32, devStat func(string) (bool, uint64, error)) (gb300FabricDevice, error) {
	resolved, err := filepath.EvalSymlinks(devPath)
	if err != nil {
		return gb300FabricDevice{}, fmt.Errorf("cannot resolve %q: %w", devPath, err)
	}
	isChar, rdev, err := devStat(resolved)
	if err != nil {
		return gb300FabricDevice{}, fmt.Errorf("cannot stat %q: %w", resolved, err)
	}
	if !isChar {
		return gb300FabricDevice{}, fmt.Errorf("%q is not a character device", resolved)
	}
	gotMajor, gotMinor := unix.Major(rdev), unix.Minor(rdev)
	if gotMajor != wantMajor || gotMinor != wantMinor {
		return gb300FabricDevice{}, fmt.Errorf("%q has device number %d:%d, want %d:%d", resolved, gotMajor, gotMinor, wantMajor, wantMinor)
	}
	return gb300FabricDevice{
		hostPath:      resolved,
		containerPath: devPath,
	}, nil
}

// gb300IMEXChannelDevs discovers the host IMEX channel character devices under
// <devRoot>/nvidia-caps-imex-channels/channel<N> and validates each resolved
// node against the "nvidia-caps-imex-channels" major in <procRoot>/devices and
// minor N. Symlinks are resolved so hostPath holds the real device node for
// oci.WithDevices while containerPath keeps the discovered path. An absent
// channel directory (fs.ErrNotExist) is returned as a skipped error; all other
// errors fail closed.
func gb300IMEXChannelDevs(devRoot, procRoot string, devStat func(string) (bool, uint64, error)) ([]gb300FabricDevice, []error, error) {
	chanDir := filepath.Join(devRoot, "nvidia-caps-imex-channels")
	entries, err := os.ReadDir(chanDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, []error{fmt.Errorf("cannot read %q: %w", chanDir, err)}, nil
		}
		return nil, nil, fmt.Errorf("cannot read %q: %w", chanDir, err)
	}
	var devs []gb300FabricDevice
	hasMajor := false
	var wantMajor uint32
	for _, entry := range entries {
		m := imexChannelNameRegexp.FindStringSubmatch(entry.Name())
		if m == nil {
			continue
		}
		minor64, err := strconv.ParseUint(m[1], 10, 32)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid IMEX channel number in %q: %w", entry.Name(), err)
		}
		if !hasMajor {
			wantMajor, err = readCharDeviceMajor(procRoot, imexChannelDriverName)
			if err != nil {
				return nil, nil, err
			}
			hasMajor = true
		}
		devPath := filepath.Join(chanDir, entry.Name())
		dev, err := resolveGB300CharDevice(devPath, wantMajor, uint32(minor64), devStat)
		if err != nil {
			return nil, nil, err
		}
		devs = append(devs, dev)
	}
	return devs, nil, nil
}

// gb300CapDevs discovers the NVIDIA capability character devices for
// fabric-imex-mgmt and mncc-mgmt under <devRoot>/nvidia-caps/ using minors
// from <procRoot>/driver/nvidia/capabilities/<name> and the "nvidia-caps" major
// from <procRoot>/devices. Absent proc files or capability nodes
// (fs.ErrNotExist) are returned as skipped errors; all other errors fail closed.
func gb300CapDevs(devRoot, procRoot string, devStat func(string) (bool, uint64, error)) ([]gb300FabricDevice, []error, error) {
	var devs []gb300FabricDevice
	var skipped []error
	hasMajor := false
	var capMajor uint32
	for _, capName := range gb300FabricCapNames {
		procPath := filepath.Join(procRoot, "driver", "nvidia", "capabilities", capName)
		devPath, minor, skipErr, err := lookupGB300CapNode(devRoot, procPath)
		if err != nil {
			return nil, nil, err
		}
		if skipErr != nil {
			skipped = append(skipped, skipErr)
			continue
		}
		if !hasMajor {
			capMajor, err = readCharDeviceMajor(procRoot, nvidiaCapsDriverName)
			if err != nil {
				return nil, nil, err
			}
			hasMajor = true
		}
		dev, err := resolveGB300CharDevice(devPath, capMajor, minor, devStat)
		if err != nil {
			return nil, nil, fmt.Errorf("capability %q: %w", procPath, err)
		}
		devs = append(devs, dev)
	}
	return devs, skipped, nil
}

func lookupGB300CapNode(devRoot, procPath string) (string, uint32, error, error) {
	data, err := os.ReadFile(procPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", 0, fmt.Errorf("cannot read %q: %w", procPath, err), nil
		}
		return "", 0, nil, fmt.Errorf("cannot read %q: %w", procPath, err)
	}
	minor, err := parseNvidiaCapMinor(data)
	if err != nil {
		return "", 0, nil, fmt.Errorf("cannot parse %q: %w", procPath, err)
	}
	devPath := filepath.Join(devRoot, "nvidia-caps", fmt.Sprintf("nvidia-cap%d", minor))
	if _, err := os.Lstat(devPath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", 0, fmt.Errorf("capability %q: cannot stat %q: %w", procPath, devPath, err), nil
		}
		return "", 0, nil, fmt.Errorf("capability %q: cannot lstat %q: %w", procPath, devPath, err)
	}
	return devPath, minor, nil, nil
}

func readCharDeviceMajor(procRoot, driverName string) (uint32, error) {
	procDevicesPath := filepath.Join(procRoot, "devices")
	data, err := os.ReadFile(procDevicesPath)
	if err != nil {
		return 0, fmt.Errorf("cannot read %q: %w", procDevicesPath, err)
	}
	major, err := parseCharDeviceMajor(data, driverName)
	if err != nil {
		return 0, fmt.Errorf("cannot parse %q: %w", procDevicesPath, err)
	}
	return major, nil
}

// parseCharDeviceMajor parses the major number for driverName from the
// "Character devices:" section of /proc/devices.
func parseCharDeviceMajor(data []byte, driverName string) (uint32, error) {
	inCharSection := false
	found := false
	var major uint32
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if !inCharSection {
			if trimmed == "Character devices:" {
				inCharSection = true
			}
			continue
		}
		if strings.HasSuffix(trimmed, ":") {
			break
		}
		fields := strings.Fields(trimmed)
		if len(fields) != 2 || fields[1] != driverName {
			continue
		}
		if found {
			return 0, fmt.Errorf("duplicate character device driver %q", driverName)
		}
		found = true
		n, err := strconv.ParseUint(fields[0], 10, 32)
		if err != nil {
			return 0, fmt.Errorf("invalid major %q for character device driver %q: %w", fields[0], driverName, err)
		}
		major = uint32(n)
	}
	if !inCharSection {
		return 0, errors.New(`missing "Character devices:" section`)
	}
	if !found {
		return 0, fmt.Errorf("missing character device driver %q", driverName)
	}
	return major, nil
}

// parseNvidiaCapMinor parses the "DeviceFileMinor: <N>" line from an NVIDIA
// driver /proc/driver/nvidia/capabilities/<name> file.
func parseNvidiaCapMinor(data []byte) (uint32, error) {
	found := false
	var minor uint32
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
		n, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("invalid DeviceFileMinor %q: %w", val, err)
		}
		minor = uint32(n)
	}
	if !found {
		return 0, errors.New("missing DeviceFileMinor")
	}
	return minor, nil
}
