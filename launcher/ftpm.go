package launcher

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

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

var (
	// ftpmSymlinkNames are the deterministic TrustZone fTPM symlink names created by udev on GB300 hosts.
	ftpmSymlinkNames = []string{"ftpm", "ftpmrm"}
	// dtpmSymlinkNames are the host-only Dauntless dTPM symlink names that must never alias an fTPM device.
	dtpmSymlinkNames = []string{"dtpm", "dtpmrm"}
	// ftpmHostDir is overridden in unit tests to simulate /dev fTPM symlinks.
	ftpmHostDir = defaultFTPMHostDir
)

// isCharDevice checks if a given path is a character device.
func isCharDevice(path string) (bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	// Character devices have both ModeDevice and ModeCharDevice set.
	return fi.Mode().Type() == (os.ModeDevice | os.ModeCharDevice), nil
}

// ftpmDevice represents a TrustZone fTPM character device node to pass into the workload container.
type ftpmDevice struct {
	// hostPath is the resolved host character device node, e.g. /dev/tpm1 or /dev/tpmrm1.
	hostPath string
	// containerPath is where the device node appears in the container, e.g. /dev/ftpm or /dev/ftpmrm.
	containerPath string
}

// discoverFTPMDevs resolves the GB300 TrustZone fTPM udev symlinks (ftpm, ftpmrm) in hostDir
// to their underlying character device nodes and maps them into containerDir.
//
// If neither ftpm nor ftpmrm exists on the host (e.g., on environments where the fTPM Secure
// Partition is not enabled in firmware), discoverFTPMDevs returns (nil, nil).
// Discovery fails closed if only one of the two symlinks exists, if a symlink is dangling,
// if a target is not a character device, if both symlinks resolve to the same device, or if
// an fTPM symlink resolves to a host Dauntless dTPM device.
func discoverFTPMDevs(hostDir, containerDir string, charDevChecker func(string) (bool, error)) ([]ftpmDevice, error) {
	if containerDir == "" {
		return nil, errors.New("container directory for fTPM devices is unspecified")
	}
	if charDevChecker == nil {
		charDevChecker = isCharDevice
	}

	var presentLinks, missingLinks []string
	for _, name := range ftpmSymlinkNames {
		link := filepath.Join(hostDir, name)
		_, err := os.Lstat(link)
		switch {
		case err == nil:
			presentLinks = append(presentLinks, link)
		case errors.Is(err, os.ErrNotExist):
			missingLinks = append(missingLinks, link)
		default:
			return nil, fmt.Errorf("failed to lstat fTPM path %q: %w", link, err)
		}
	}

	if len(presentLinks) == 0 {
		return nil, nil
	}
	if len(missingLinks) > 0 {
		return nil, fmt.Errorf("incomplete GB300 fTPM device symlinks: missing %q while %q is present", missingLinks[0], presentLinks[0])
	}

	// Guard against misconfigured udev rules aliasing an fTPM symlink onto a Dauntless dTPM node.
	dtpmDevs := make(map[string]string, len(dtpmSymlinkNames))
	for _, name := range dtpmSymlinkNames {
		dtpmLink := filepath.Join(hostDir, name)
		if _, err := os.Lstat(dtpmLink); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, fmt.Errorf("failed to lstat dTPM path %q: %w", dtpmLink, err)
		}
		resolvedDTPM, err := filepath.EvalSymlinks(dtpmLink)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve dTPM symlink %q: %w", dtpmLink, err)
		}
		dtpmDevs[resolvedDTPM] = dtpmLink
	}

	var devs []ftpmDevice
	devSymlink := make(map[string]string, len(ftpmSymlinkNames))
	for _, name := range ftpmSymlinkNames {
		link := filepath.Join(hostDir, name)

		// Resolve the symlink: containerd's oci.WithDevices lstat()s hostPath and rejects symlinks.
		dev, err := filepath.EvalSymlinks(link)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve fTPM symlink %q: %w", link, err)
		}
		isChar, err := charDevChecker(dev)
		if err != nil {
			return nil, fmt.Errorf("failed to check fTPM device %q: %w", dev, err)
		}
		if !isChar {
			return nil, fmt.Errorf("symlink %q for fTPM resolves to %q, which is not a character device", link, dev)
		}
		if dtpmLink, ok := dtpmDevs[dev]; ok {
			return nil, fmt.Errorf("fTPM symlink %q resolves to Dauntless dTPM device %q (matched %q)", link, dev, dtpmLink)
		}
		if prev, ok := devSymlink[dev]; ok {
			return nil, fmt.Errorf("both fTPM symlinks %q and %q resolve to the same device %q", prev, link, dev)
		}
		devSymlink[dev] = link

		devs = append(devs, ftpmDevice{
			hostPath:      dev,
			containerPath: filepath.Join("/", containerDir, name),
		})
	}
	return devs, nil
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
