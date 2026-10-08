package launchermount

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/opencontainers/runtime-spec/specs-go"
)

var lssdNameRegexp = regexp.MustCompile(`^google-local-nvme-ssd-\d+$`)

const (
	// DefaultLSSDHostPath is the default host path to search for LSSDs.
	DefaultLSSDHostPath = "/dev/disk/by-id"
	// DefaultLSSDContainerPath is the default container path where the LSSDs will be mounted.
	DefaultLSSDContainerPath = DefaultLSSDHostPath
)

// isBlockDevice is defined as a variable to allow overriding it in unit tests.
var isBlockDevice = func(path string) (bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, err
	}

	// Block devices have only ModeDevice set.
	return fi.Mode().Type() == os.ModeDevice, nil
}

// LSSDMount bind-mounts a Local SSD block device node into the container.
type LSSDMount struct {
	// source is the host block device path.
	source string
	// destination is the container path.
	destination string
}

// CreateLSSDMounts enumerates all Local SSDs and returns mount configurations for paththrough.
// It finds `google-local-nvme-ssd-<N>` symlinks in hostPath, e.g., `<hostPath>/google-local-nvme-ssd-0`,
// and creates mount specs to mount them inside the container with the same basename, e.g., into `<containerDestPath>/google-local-nvme-ssd-0`.
func CreateLSSDMounts(hostPath, containerDestPath string) ([]LSSDMount, error) {
	if containerDestPath == "" {
		return nil, errors.New("local SSD mounts destination unspecified")
	}

	links, err := filepath.Glob(filepath.Join(hostPath, "google-local-nvme-ssd-*"))
	if err != nil {
		return nil, fmt.Errorf("failed to glob local SSDs in %q: %w", hostPath, err)
	}

	var lssdLinks []string
	for _, link := range links {
		if !lssdNameRegexp.MatchString(filepath.Base(link)) {
			continue
		}

		lssdLinks = append(lssdLinks, link)
	}

	var mounts []LSSDMount
	devSymlink := make(map[string]string) // Resolved device path -> symlink path.
	for _, link := range lssdLinks {
		dev, err := filepath.EvalSymlinks(link)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve local SSD symlink %q: %w", link, err)
		}
		isBlk, err := isBlockDevice(dev)
		if err != nil {
			return nil, fmt.Errorf("failed to check local SSD device %q: %w", dev, err)
		}
		if !isBlk {
			return nil, fmt.Errorf("local SSD symlink %q resolves to %q, which is not a block device", link, dev)
		}
		// Exposing one device under two names could corrupt data, e.g. when
		// the workload stripes a RAID 0 array across them.
		if prev, ok := devSymlink[dev]; ok {
			return nil, fmt.Errorf("local SSD symlinks %q and %q resolve to the same device %q", prev, link, dev)
		}
		devSymlink[dev] = link

		mounts = append(mounts, LSSDMount{
			source:      dev,
			destination: filepath.Join("/", containerDestPath, filepath.Base(link)),
		})
	}
	return mounts, nil
}

// SpecsMount returns the OCI runtime spec Mount that bind-mounts the Local SSD
// block device node into the container.
func (l LSSDMount) SpecsMount() specs.Mount {
	return specs.Mount{
		Type:        "bind",
		Source:      l.source,
		Destination: l.destination,
		Options:     []string{"bind", "rw"}, // Passthrough
	}
}

// Mountpoint returns the path of the Local SSD device node in the container.
func (l LSSDMount) Mountpoint() string {
	return l.destination
}
