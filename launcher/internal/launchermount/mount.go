// Package launchermount defines mount types for the launcher workload.
package launchermount

import "github.com/opencontainers/runtime-spec/specs-go"

// Key-value constants for mount configurations.
// Keys are used to specify the specific mount configuration.
// For example, TypeKey is used to specify the type of mount.
// Consts not suffixed with Key are constant values for given mount configs.
const (
	TypeKey        = "type"
	SourceKey      = "source"
	DestinationKey = "destination"
	SizeKey        = "size"
	TypeTmpfs      = "tmpfs"
)

var (
	// AllMountKeys are all possible mount configuration key names.
	AllMountKeys = []string{TypeKey, SourceKey, DestinationKey, SizeKey}
)

// Mount is the interface to implement for a new container launcher mount type.
type Mount interface {
	// SpecsMount converts the Mount type to an OCI spec Mount.
	SpecsMount() specs.Mount
	// The absolute path mount point for this mount in the container.
	// Stored as Destination in specs.Mount.
	Mountpoint() string
}
