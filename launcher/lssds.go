package launcher

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

const (
	// defaultLSSDHostDir is the default host directory to search for LSSDs.
	defaultLSSDHostDir = "/dev/disk/by-id"
	// defaultLSSDContainerDir is the default container directory where the LSSDs will be exposed.
	defaultLSSDContainerDir = defaultLSSDHostDir
)

var lssdNameRegexp = regexp.MustCompile(`^google-local-nvme-ssd-\d+$`)

// isBlockDevice checks if a given path is a block device.
func isBlockDevice(path string) (bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, err
	}

	// Block devices have only ModeDevice set.
	return fi.Mode().Type() == os.ModeDevice, nil
}

// lssdDevice represents a Local SSD device node.
type lssdDevice struct {
	// hostPath is the resolved host device node, e.g. /dev/nvme0n1, not the by-id symlink.
	hostPath string
	// containerPath is where the device node appears in the container, e.g. /dev/disk/by-id/google-local-nvme-ssd-0.
	containerPath string
}

// discoverLSSDDevs returns the Local SSD block devices.
// It resolves Local SSD symlinks in hostDir and maps each device to the container.
// It returns an error if a link is dangling, does not resolve to a block device, or if two links resolve to the same device.
// When blockDevChecker is nil, a default block device checker is used.
func discoverLSSDDevs(hostDir, containerDir string, blockDevChecker func(string) (bool, error)) ([]lssdDevice, error) {
	if containerDir == "" {
		return nil, errors.New("container directory for Local SSDs is unspecified")
	}
	if blockDevChecker == nil {
		blockDevChecker = isBlockDevice
	}

	entries, err := os.ReadDir(hostDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil // No by-id directory means no Local SSDs.
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read %q: %w", hostDir, err)
	}

	var devs []lssdDevice
	devSymlink := make(map[string]string) // Resolved device path -> symlink path.
	for _, e := range entries {
		if !lssdNameRegexp.MatchString(e.Name()) {
			continue
		}
		link := filepath.Join(hostDir, e.Name())

		// Resolve the link: containerd's oci.WithDevices lstat()s the path and rejects symlinks.
		dev, err := filepath.EvalSymlinks(link)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve Local SSD symlink %q: %w", link, err)
		}
		isBlock, err := blockDevChecker(dev)
		if err != nil {
			return nil, fmt.Errorf("failed to check Local SSD device %q: %w", dev, err)
		}
		if !isBlock {
			return nil, fmt.Errorf("symlink %q for a Local SSD resolves to %q, which is not a block device", link, dev)
		}
		// Exposing one device under two names could corrupt data, e.g., when the workload stripes a RAID 0 array across them.
		if prev, ok := devSymlink[dev]; ok {
			return nil, fmt.Errorf("both Local SSD symlinks %q and %q resolve to the same device %q", prev, link, dev)
		}
		devSymlink[dev] = link

		devs = append(devs, lssdDevice{
			hostPath:      dev,
			containerPath: filepath.Join("/", containerDir, e.Name()),
		})
	}
	return devs, nil
}
