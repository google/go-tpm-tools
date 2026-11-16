package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"github.com/google/go-tpm-tools/launcher/internal/logging"
)

const (
	// defaultLSSDHostDir is the default host directory to search for LSSDs.
	defaultLSSDHostDir = "/dev/disk/by-id"
	// defaultLSSDContainerDir is the default container directory where the LSSDs will be exposed.
	defaultLSSDContainerDir = defaultLSSDHostDir

	// instanceDisksQuery is the metadata server path listing the disks attached to the instance.
	instanceDisksQuery = "instance/disks/?recursive=true"
	// lssdDiskType is the disk type value for Local SSDs in the metadata server.
	lssdDiskType = "LOCAL-SSD"
	// lssdInterface is the disk interface value for NVMe Local SSDs in the metadata server.
	lssdInterface = "NVME"
	// lssdWaitTimeout is the maximum time waitForLSSDs waits for all Local SSD links.
	lssdWaitTimeout = 30 * time.Second
	// lssdPollInterval is the interval between checks in waitForLSSDs.
	lssdPollInterval = time.Second
)

var lssdNameRegexp = regexp.MustCompile(`^google-local-nvme-ssd-\d+$`)

// metadataGetter is the subset of *metadata.Client used by waitForLSSDs.
type metadataGetter interface {
	GetWithContext(ctx context.Context, suffix string) (string, error)
}

// instanceDisk is one entry of the metadata server's instance/disks list.
type instanceDisk struct {
	Interface string `json:"interface"`
	Type      string `json:"type"`
}

// isBlockDevice checks if a given path is a block device.
func isBlockDevice(path string) (bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, err
	}

	// Block devices have only ModeDevice set.
	return fi.Mode().Type() == os.ModeDevice, nil
}

// isInUse reports whether the block device is held by the kernel, e.g. mounted, used as swap or claimed by md/dm.
// An exclusive open fails with EBUSY in that case, which is what mkfs and wipefs rely on as well.
// The claim is released right away, holding it would make the workload's own mount fail.
func isInUse(path string) (bool, error) {
	// O_EXCL without O_CREATE: Linux fails the open of a busy block device with EBUSY.
	// O_RDONLY: closing a device opened for writing triggers a udev "change" event.
	f, err := os.OpenFile(path, os.O_RDONLY|os.O_EXCL, 0)
	if errors.Is(err, syscall.EBUSY) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, f.Close()
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
// It returns an error if a link is dangling, does not resolve to a block device, resolves to a device in use, or if two links resolve to the same device.
// When blockDevChecker or inUseChecker is nil, the default checker is used.
func discoverLSSDDevs(hostDir, containerDir string, blockDevChecker, inUseChecker func(string) (bool, error)) ([]lssdDevice, error) {
	if containerDir == "" {
		return nil, errors.New("container directory for Local SSDs is unspecified")
	}
	if blockDevChecker == nil {
		blockDevChecker = isBlockDevice
	}
	if inUseChecker == nil {
		inUseChecker = isInUse
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
		// A device the host still uses, e.g. a mounted one, must not be handed to the workload.
		inUse, err := inUseChecker(dev)
		if err != nil {
			return nil, fmt.Errorf("failed to check whether Local SSD device %q is in use: %w", dev, err)
		}
		if inUse {
			return nil, fmt.Errorf("symlink %q for a Local SSD resolves to %q, which is in use by the host", link, dev)
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

// waitForLSSDs waits up to timeout until hostDir has links for all Local SSDs reported by the metadata server.
// It fails on timeout or if more Local SSD links exist than reported.
// If the metadata server lists no Local SSDs, it returns nil immediately.
func waitForLSSDs(ctx context.Context, mds metadataGetter, hostDir string, timeout, poll time.Duration, logger logging.Logger) error {
	want, err := attachedLSSDCount(ctx, mds)
	if err != nil {
		return fmt.Errorf("failed to count the attached Local SSDs: %w", err)
	}
	if want == 0 {
		logger.Info("the metadata server lists no Local SSDs")
		return nil
	}
	logger.Info(fmt.Sprintf("waiting for %d Local SSD links", want))

	deadline := time.Now().Add(timeout)
	for {
		got, err := presentLSSDCount(hostDir)
		if err != nil {
			return err
		}
		if got == want {
			return nil
		}
		if got > want {
			return fmt.Errorf("unexpected Local SSD links: got %d, want %d", got, want)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("not all Local SSD links appeared within %v: got %d, want %d", timeout, got, want)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}

// attachedLSSDCount returns the number of NVMe Local SSDs reported by the metadata server.
func attachedLSSDCount(ctx context.Context, mds metadataGetter) (int, error) {
	data, err := mds.GetWithContext(ctx, instanceDisksQuery)
	if err != nil {
		return 0, err
	}
	var disks []instanceDisk
	if err := json.Unmarshal([]byte(data), &disks); err != nil {
		return 0, fmt.Errorf("failed to parse %q: %w", instanceDisksQuery, err)
	}

	count := 0
	for _, d := range disks {
		if d.Type != lssdDiskType {
			continue
		}
		if d.Interface != lssdInterface {
			// Fail closed: discoverLSSDDevs only exposes NVMe Local SSD links.
			return 0, fmt.Errorf("unsupported Local SSD interface %q, want %q", d.Interface, lssdInterface)
		}
		count++
	}
	return count, nil
}

// presentLSSDCount returns the number of Local SSD links in hostDir.
func presentLSSDCount(hostDir string) (int, error) {
	entries, err := os.ReadDir(hostDir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil // udev creates /dev/disk/by-id with the first disk link.
	}
	if err != nil {
		return 0, fmt.Errorf("failed to read %q: %w", hostDir, err)
	}
	count := 0
	for _, e := range entries {
		if lssdNameRegexp.MatchString(e.Name()) {
			count++
		}
	}
	return count, nil
}
