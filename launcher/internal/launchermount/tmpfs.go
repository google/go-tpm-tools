package launchermount

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/opencontainers/runtime-spec/specs-go"
)

var errTmpfsMustHaveDest = errors.New("mount type \"tmpfs\" must have destination specified")

// TmpfsMount creates a launcher mount type backed by tmpfs, with an optional
// size. If size is not specified, it is 50% of memory.
// Example input: `type=tmpfs,source=tmpfs,destination=/tmpmount`
// `type=tmpfs,source=tmpfs,destination=/sizedtmpmount,size=123345`
type TmpfsMount struct {
	// If the path is relative, it will be interpreted as relative to "/".
	Destination string
	// Size in bytes. No support for k, m, g suffixes.
	Size uint64
}

// CreateTmpfsMount takes a map of tmpfs options, with keys defined in the spec package.
// Typically, this is called when creating a LaunchSpec and should not be used
// in other settings.
func CreateTmpfsMount(mountMap map[string]string) (TmpfsMount, error) {
	if val := mountMap[TypeKey]; val != TypeTmpfs {
		return TmpfsMount{}, fmt.Errorf("received wrong mount type %v, expected %v", val, TypeTmpfs)
	}
	delete(mountMap, TypeKey)

	if val := mountMap[SourceKey]; val != TypeTmpfs {
		return TmpfsMount{}, fmt.Errorf("received wrong mount source %v, expected %v", val, TypeTmpfs)
	}
	delete(mountMap, SourceKey)

	dst := mountMap[DestinationKey]
	if dst == "" {
		return TmpfsMount{}, errTmpfsMustHaveDest
	}
	if !filepath.IsAbs(dst) {
		dst = filepath.Join("/", dst)
	}
	delete(mountMap, DestinationKey)
	mnt := TmpfsMount{Destination: dst}

	szStr, ok := mountMap[SizeKey]
	if ok {
		sz, err := strconv.ParseUint(szStr, 10, 64)
		if err != nil {
			return TmpfsMount{}, fmt.Errorf("failed to convert size option \"%v\" to uint64: %v", szStr, err)
		}
		mnt.Size = sz
		delete(mountMap, SizeKey)
	}

	if len(mountMap) != 0 {
		return TmpfsMount{}, fmt.Errorf("received unknown mount options for tmpfs mount: %+v", mountMap)
	}
	return mnt, nil
}

// SpecsMount returns the OCI runtime spec Mount for the given TmpfsMount.
func (tm TmpfsMount) SpecsMount() specs.Mount {
	specsMnt := specs.Mount{Type: TypeTmpfs,
		Source:      TypeTmpfs,
		Destination: tm.Destination,
		Options:     []string{"nosuid", "noexec", "nodev"}}
	if tm.Size != 0 {
		specsMnt.Options = append(specsMnt.Options, fmt.Sprintf("size=%s", strconv.FormatUint(tm.Size, 10)))
	}
	return specsMnt
}

// Mountpoint gives the place in the container where the tmpfs is mounted.
func (tm TmpfsMount) Mountpoint() string {
	return tm.Destination
}
