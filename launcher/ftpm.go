package launcher

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"syscall"

	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/oci"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

const (
	// defaultFTPMHostDir is the default host directory containing the udev fTPM symlinks.
	defaultFTPMHostDir = "/dev"
	// defaultFTPMContainerDir is the default container directory where the fTPM devices will be exposed.
	defaultFTPMContainerDir = defaultFTPMHostDir
	// ftpmContainerFileMode grants read/write access to both root and non-root workload users inside the container.
	ftpmContainerFileMode os.FileMode = 0o666
)

// tpmLinkNames are the udev symlink names for one TPM chip: the raw device and its kernel resource manager.
type tpmLinkNames struct {
	// kind is a human-readable TPM kind used in error messages, e.g. "fTPM" or "dTPM".
	kind string
	// raw is the symlink name for the raw TPM device, which must resolve to a tpm<N> node.
	raw string
	// rm is the symlink name for the resource manager device, which must resolve to the tpmrm<N> node with the same <N>.
	rm string
}

var (
	// ftpmLinks are the deterministic TrustZone fTPM symlink names created by udev on GB300 hosts.
	ftpmLinks = tpmLinkNames{kind: "fTPM", raw: "ftpm", rm: "ftpmrm"}
	// dtpmLinks are the host-only Dauntless dTPM symlink names that must never alias an fTPM device.
	dtpmLinks = tpmLinkNames{kind: "dTPM", raw: "dtpm", rm: "dtpmrm"}

	// The kernel names TPM character devices tpm<N> and tpmrm<N> (drivers/char/tpm/tpm-chip.c).
	tpmRawNodeRegexp = regexp.MustCompile(`^tpm(\d+)$`)
	tpmRMNodeRegexp  = regexp.MustCompile(`^tpmrm(\d+)$`)

	// findGB300FTPMDevs discovers the host fTPM devices to pass into the workload container.
	// It is overridden in unit tests to keep createOCISpecOpts hermetic.
	findGB300FTPMDevs = func() ([]ftpmDevice, error) {
		return discoverFTPMDevs(defaultFTPMHostDir, defaultFTPMContainerDir, charDevStat)
	}
)

// charDevStat follows symlinks in path and reports whether the result is a character device.
// For a character device, it also returns the device number (st_rdev, i.e. major:minor).
func charDevStat(path string) (isChar bool, rdev uint64, err error) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, 0, err
	}
	// Character devices have both ModeDevice and ModeCharDevice set.
	if fi.Mode().Type() != os.ModeDevice|os.ModeCharDevice {
		return false, 0, nil
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false, 0, fmt.Errorf("unexpected stat type %T for %q", fi.Sys(), path)
	}
	return true, uint64(st.Rdev), nil
}

// ftpmDevice represents a TrustZone fTPM character device node to pass into the workload container.
type ftpmDevice struct {
	// hostPath is the resolved host character device node, e.g. /dev/tpm1 or /dev/tpmrm1.
	hostPath string
	// containerPath is where the device node appears in the container, e.g. /dev/ftpm or /dev/ftpmrm.
	containerPath string
}

// tpmNode is a udev TPM symlink resolved to its character device node.
type tpmNode struct {
	// name is the symlink name, e.g. "ftpm".
	name string
	// link is the symlink path, e.g. /dev/ftpm.
	link string
	// dev is the resolved device node path, e.g. /dev/tpm1.
	dev string
	// rdev is the device number (major:minor) of dev.
	rdev uint64
}

// resolvedTPM is a validated raw/resource-manager pair of TPM device nodes for one TPM chip.
type resolvedTPM struct {
	// index is the kernel TPM index <N> shared by the tpm<N> and tpmrm<N> nodes.
	index string
	raw   tpmNode
	rm    tpmNode
}

// discoverFTPMDevs resolves the GB300 TrustZone fTPM udev symlinks (ftpm, ftpmrm) in hostDir
// to their underlying character device nodes and maps them into containerDir.
//
// If neither ftpm nor ftpmrm exists on the host (e.g., on environments where the fTPM Secure
// Partition is not enabled in firmware), discoverFTPMDevs returns (nil, nil).
// Otherwise, discovery fails closed unless:
//   - both ftpm and ftpmrm exist and are symlinks (not device nodes or other files),
//   - they resolve to character devices named tpm<N> and tpmrm<N> with the same <N>,
//   - they resolve to two distinct device numbers, and
//   - if the Dauntless dTPM symlinks (dtpm, dtpmrm) exist, they pass the same checks with an
//     index <M> != <N>, and no fTPM device number matches a dTPM device number.
//
// devStat follows symlinks and reports whether a path is a character device and its device
// number. When devStat is nil, charDevStat is used.
func discoverFTPMDevs(hostDir, containerDir string, devStat func(string) (bool, uint64, error)) ([]ftpmDevice, error) {
	if containerDir == "" {
		return nil, errors.New("container directory for fTPM devices is unspecified")
	}
	if devStat == nil {
		devStat = charDevStat
	}

	ftpm, err := resolveTPMLinks(hostDir, ftpmLinks, devStat)
	if err != nil {
		return nil, err
	}
	if ftpm == nil {
		return nil, nil
	}

	// Guard against misconfigured udev rules aliasing an fTPM symlink onto a Dauntless dTPM node.
	dtpm, err := resolveTPMLinks(hostDir, dtpmLinks, devStat)
	if err != nil {
		return nil, err
	}
	if dtpm != nil {
		if ftpm.index == dtpm.index {
			return nil, fmt.Errorf("fTPM symlinks resolve to the Dauntless dTPM device index %s (%q -> %q, %q -> %q)",
				ftpm.index, ftpm.raw.link, ftpm.raw.dev, dtpm.raw.link, dtpm.raw.dev)
		}
		for _, f := range []tpmNode{ftpm.raw, ftpm.rm} {
			for _, d := range []tpmNode{dtpm.raw, dtpm.rm} {
				if f.rdev == d.rdev {
					return nil, fmt.Errorf("fTPM symlink %q resolves to %q, which has the same device number as Dauntless dTPM device %q (matched %q)",
						f.link, f.dev, d.dev, d.link)
				}
			}
		}
	}

	var devs []ftpmDevice
	for _, n := range []tpmNode{ftpm.raw, ftpm.rm} {
		devs = append(devs, ftpmDevice{
			hostPath:      n.dev,
			containerPath: filepath.Join("/", containerDir, n.name),
		})
	}
	return devs, nil
}

// resolveTPMLinks resolves and validates the raw and resource manager symlinks for one TPM chip in hostDir.
// It returns (nil, nil) if neither symlink exists, and an error if only one exists or if any check fails.
func resolveTPMLinks(hostDir string, names tpmLinkNames, devStat func(string) (bool, uint64, error)) (*resolvedTPM, error) {
	var present, missing []string
	for _, name := range []string{names.raw, names.rm} {
		link := filepath.Join(hostDir, name)
		fi, err := os.Lstat(link)
		switch {
		case err == nil:
			// filepath.EvalSymlinks returns a non-symlink path unchanged, so a device node
			// created directly at this path would otherwise bypass the checks below.
			if fi.Mode()&os.ModeSymlink == 0 {
				return nil, fmt.Errorf("%s path %q is not a symlink", names.kind, link)
			}
			present = append(present, link)
		case errors.Is(err, os.ErrNotExist):
			missing = append(missing, link)
		default:
			return nil, fmt.Errorf("failed to lstat %s path %q: %w", names.kind, link, err)
		}
	}
	if len(present) == 0 {
		return nil, nil
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("incomplete GB300 %s device symlinks: missing %q while %q is present", names.kind, missing, present)
	}

	raw, rawIndex, err := resolveTPMNode(hostDir, names.kind, names.raw, tpmRawNodeRegexp, devStat)
	if err != nil {
		return nil, err
	}
	rm, rmIndex, err := resolveTPMNode(hostDir, names.kind, names.rm, tpmRMNodeRegexp, devStat)
	if err != nil {
		return nil, err
	}
	if rawIndex != rmIndex {
		return nil, fmt.Errorf("%s symlinks resolve to different TPM indexes: %q -> %q, %q -> %q",
			names.kind, raw.link, raw.dev, rm.link, rm.dev)
	}
	if raw.rdev == rm.rdev {
		return nil, fmt.Errorf("both %s symlinks %q and %q resolve to the same device number (%q, %q)",
			names.kind, raw.link, rm.link, raw.dev, rm.dev)
	}
	return &resolvedTPM{index: rawIndex, raw: raw, rm: rm}, nil
}

// resolveTPMNode resolves the symlink hostDir/name to a character device whose base name matches nodeRegexp,
// and returns the resolved node and its kernel TPM index.
func resolveTPMNode(hostDir, kind, name string, nodeRegexp *regexp.Regexp, devStat func(string) (bool, uint64, error)) (tpmNode, string, error) {
	link := filepath.Join(hostDir, name)
	// Resolve the symlink: containerd's oci.WithDevices lstat()s hostPath and rejects symlinks.
	dev, err := filepath.EvalSymlinks(link)
	if err != nil {
		return tpmNode{}, "", fmt.Errorf("failed to resolve %s symlink %q: %w", kind, link, err)
	}
	isChar, rdev, err := devStat(dev)
	if err != nil {
		return tpmNode{}, "", fmt.Errorf("failed to check %s device %q: %w", kind, dev, err)
	}
	if !isChar {
		return tpmNode{}, "", fmt.Errorf("symlink %q for %s resolves to %q, which is not a character device", link, kind, dev)
	}
	m := nodeRegexp.FindStringSubmatch(filepath.Base(dev))
	if m == nil {
		return tpmNode{}, "", fmt.Errorf("symlink %q for %s resolves to %q, which does not match %s", link, kind, dev, nodeRegexp)
	}
	return tpmNode{name: name, link: link, dev: dev, rdev: rdev}, m[1], nil
}

// withFTPMDevice adds a resolved fTPM character device to the container OCI spec
// at containerPath with "rw" device-cgroup access and file mode 0666 so both
// root and non-root workload users inside the container can access the fTPM.
func withFTPMDevice(hostPath, containerPath string) oci.SpecOpts {
	return func(ctx context.Context, client oci.Client, c *containers.Container, s *oci.Spec) error {
		if s.Linux == nil {
			s.Linux = &specs.Linux{}
		}
		if s.Linux.Resources == nil {
			s.Linux.Resources = &specs.LinuxResources{}
		}
		prevLen := len(s.Linux.Devices)
		if err := oci.WithDevices(hostPath, containerPath, "rw")(ctx, client, c, s); err != nil {
			return err
		}
		for i := prevLen; i < len(s.Linux.Devices); i++ {
			fm := ftpmContainerFileMode
			s.Linux.Devices[i].FileMode = &fm
		}
		return nil
	}
}
