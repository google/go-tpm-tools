package spec

import (
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"strconv"
	"strings"
)

// LaunchPolicy contains policies on starting the container.
// The policy comes from the labels of the image.
type LaunchPolicy struct {
	AllowedEnvOverride       []string
	AllowedCmdOverride       bool
	AllowedLogRedirect       policy
	AllowedMountDestinations []string
	HardenedImageMonitoring  monitoringType
	DebugImageMonitoring     monitoringType
}

type policy int

const (
	debugOnly policy = iota
	always
	never
)

type monitoringType int

const (
	none monitoringType = iota
	memoryOnly
	health
)

// String returns LaunchPolicy details.
func (p policy) String() string {
	switch p {
	case debugOnly:
		return "debugonly"
	case always:
		return "always"
	case never:
		return "never"
	default:
		return "unspecified launch policy"
	}
}

func toPolicy(policy, s string) (policy, error) {
	s = strings.ToLower(s)
	s = strings.TrimSpace(s)

	if s == "always" {
		return always, nil
	}
	if s == "never" {
		return never, nil
	}
	if s == "debugonly" {
		return debugOnly, nil
	}
	return 0, fmt.Errorf("not a valid %s %s (must be one of [always, never, debugonly])", policy, s)
}

const (
	envOverride        = "tee.launch_policy.allow_env_override"
	cmdOverride        = "tee.launch_policy.allow_cmd_override"
	logRedirect        = "tee.launch_policy.log_redirect"
	memoryMonitoring   = "tee.launch_policy.monitoring_memory_allow"
	hardenedMonitoring = "tee.launch_policy.hardened_monitoring"
	debugMonitoring    = "tee.launch_policy.debug_monitoring"
	// Values look like a PATH list, with ':' as a separator.
	// Empty paths will be ignored and relative paths will be interpreted as
	// relative to "/".
	// Paths will be cleaned using filepath.Clean.
	mountDestinations = "tee.launch_policy.allow_mount_destinations"
)

func getMonitoringPolicy(imageLabels map[string]string, launchPolicy *LaunchPolicy, logger *log.Logger) error {
	// Old policy.
	memVal, memOk := imageLabels[memoryMonitoring]
	// New policies.
	hardenedVal, hardenedOk := imageLabels[hardenedMonitoring]
	debugVal, debugOk := imageLabels[debugMonitoring]

	var err error

	// Return an error if old/new policies are both defined
	if memOk && (hardenedOk || debugOk) {
		return fmt.Errorf("use either %s or %s/%s in image labels,- not both", memoryMonitoring, hardenedMonitoring, debugMonitoring)
	} else if memOk {
		policy, err := toPolicy(memoryMonitoring, memVal)
		if err != nil {
			return fmt.Errorf("invalid image LABEL '%s'", memoryMonitoring)
		}

		logger.Printf("%s is deprecated, use %s and %s instead", memoryMonitoring, hardenedMonitoring, debugMonitoring)

		switch policy {
		case always:
			logger.Printf("%s=always, will be treated as %s=memory_only and %s=memory_only", memoryMonitoring, hardenedMonitoring, debugMonitoring)
			launchPolicy.HardenedImageMonitoring = memoryOnly
			launchPolicy.DebugImageMonitoring = memoryOnly
		case never:
			logger.Printf("%s=never, will be treated as %s=none and %s=none", memoryMonitoring, hardenedMonitoring, debugMonitoring)
			launchPolicy.HardenedImageMonitoring = none
			launchPolicy.DebugImageMonitoring = none
		case debugOnly:
			logger.Printf("%s=debug_only, will be treated as %s=none and %s=memory_only", memoryMonitoring, hardenedMonitoring, debugMonitoring)
			launchPolicy.HardenedImageMonitoring = none
			launchPolicy.DebugImageMonitoring = memoryOnly
		}
		return nil
	}

	if hardenedOk {
		launchPolicy.HardenedImageMonitoring, err = toMonitoringType(hardenedVal)
		if err != nil {
			return fmt.Errorf("invalid monitoring type for hardened image: %v", err)
		}
	} else {
		launchPolicy.HardenedImageMonitoring = none
	}

	if debugOk {
		launchPolicy.DebugImageMonitoring, err = toMonitoringType(debugVal)
		if err != nil {
			return fmt.Errorf("invalid monitoring type for debug image: %v", err)
		}
	} else {
		launchPolicy.DebugImageMonitoring = health
	}

	return nil
}

func toMonitoringType(label string) (monitoringType, error) {
	switch strings.ToLower(label) {
	case "none":
		return none, nil
	case "memoryonly":
		return memoryOnly, nil
	case "health":
		return health, nil
	}

	return none, fmt.Errorf("invalid monitoring type: %v", label)
}

// GetLaunchPolicy takes in a map[string] string which should come from image labels,
// and will try to parse it into a LaunchPolicy. Extra fields will be ignored.
func GetLaunchPolicy(imageLabels map[string]string) (LaunchPolicy, error) {
	var err error
	launchPolicy := LaunchPolicy{}
	if v, ok := imageLabels[envOverride]; ok {
		envs := strings.Split(v, ",")
		for _, env := range envs {
			// strip out empty env name
			if env != "" {
				launchPolicy.AllowedEnvOverride = append(launchPolicy.AllowedEnvOverride, env)
			}
		}
	}

	if v, ok := imageLabels[cmdOverride]; ok {
		if launchPolicy.AllowedCmdOverride, err = strconv.ParseBool(v); err != nil {
			return LaunchPolicy{}, fmt.Errorf("invalid image LABEL '%s' (not a boolean); contact the image author", cmdOverride)
		}
	}

	// default is debug only for logRedirect
	if v, ok := imageLabels[logRedirect]; ok {
		launchPolicy.AllowedLogRedirect, err = toPolicy(logRedirect, v)
		if err != nil {
			return LaunchPolicy{}, fmt.Errorf("invalid image LABEL '%s'; contact the image author", logRedirect)
		}
	}

	if _, ok := imageLabels[memoryMonitoring]; ok {
		return LaunchPolicy{}, fmt.Errorf("%v label is deprecated - use %v and %v instead", memoryMonitoring, hardenedMonitoring, debugMonitoring)
	}

	if v, ok := imageLabels[hardenedMonitoring]; ok {
		launchPolicy.HardenedImageMonitoring, err = toMonitoringType(v)
		if err != nil {
			return LaunchPolicy{}, fmt.Errorf("invalid monitoring type for hardened image: %v", err)
		}
	} else {
		launchPolicy.HardenedImageMonitoring = none
	}

	if v, ok := imageLabels[debugMonitoring]; ok {
		launchPolicy.DebugImageMonitoring, err = toMonitoringType(v)
		if err != nil {
			return LaunchPolicy{}, fmt.Errorf("invalid monitoring type for debug image: %v", err)
		}
	} else {
		launchPolicy.DebugImageMonitoring = health
	}

	if v, ok := imageLabels[mountDestinations]; ok {

		paths := filepath.SplitList(v)
		for _, path := range paths {
			// Strip out empty path name.
			if path != "" {
				path = filepath.Clean(path)
				launchPolicy.AllowedMountDestinations = append(launchPolicy.AllowedMountDestinations, path)
			}
		}
	}

	return launchPolicy, nil
}

// Verify will use the LaunchPolicy to verify the given LaunchSpec. If the verification passed, will return nil.
// If there are multiple violations, the function will return the first error.
func (p LaunchPolicy) Verify(ls LaunchSpec) error {
	for _, e := range ls.Envs {
		if !contains(p.AllowedEnvOverride, e.Name) {
			return fmt.Errorf("env var %s is not allowed to be overridden on this image; allowed envs to be overridden: %v", e, p.AllowedEnvOverride)
		}
	}
	if !p.AllowedCmdOverride && len(ls.Cmd) > 0 {
		return fmt.Errorf("CMD is not allowed to be overridden on this image")
	}

	if p.AllowedLogRedirect == never && ls.LogRedirect.enabled() {
		return fmt.Errorf("logging redirection not allowed by image")
	}

	if p.AllowedLogRedirect == debugOnly && ls.LogRedirect.enabled() && ls.Hardened {
		return fmt.Errorf("logging redirection only allowed on debug environment by image")
	}

	monitoringPolicy := p.DebugImageMonitoring
	if ls.Hardened {
		monitoringPolicy = p.HardenedImageMonitoring
	}

	if ls.HealthMonitoringEnabled {
		// Return error if policy does not allow health monitoring.
		if monitoringPolicy != health {
			return fmt.Errorf("image does not allow health monitoring")
		}
	}

	if ls.MemoryMonitoringEnabled {
		if monitoringPolicy == none {
			return fmt.Errorf("image does not allow any monitoring")
		}
	}

	var err error
	for _, mnt := range ls.Mounts {
		err = errors.Join(err, p.verifyMountDestination(mnt.Mountpoint()))
	}
	if err != nil {
		return fmt.Errorf("destination mount points are not allowed: %v", err)
	}

	return nil
}

// verifyMountDestination assumes AllowedMountDestinations contains
// `filepath.Clean`ed paths.
func (p LaunchPolicy) verifyMountDestination(dstPath string) error {
	if !filepath.IsAbs(dstPath) {
		return fmt.Errorf("received a non-absolute destination path: %v", dstPath)
	}
	dstPath = filepath.Clean(dstPath)
	for _, allowDst := range p.AllowedMountDestinations {
		if !filepath.IsAbs(allowDst) {
			return fmt.Errorf("received a non-absolute allowed destination path: %v", allowDst)
		}
		rel, err := filepath.Rel(allowDst, dstPath)
		if err != nil {
			return err
		}

		// If dest is not the parent dir relative to the allowed mountpoint
		// or dest is not relative from the allowed's parent directory, then
		// dest must be a child (or the exact same directory).
		if rel != ".." && !strings.HasPrefix(rel, "../") {
			return nil
		}
	}
	return fmt.Errorf("destination mount point \"%v\" is invalid: policy only allows mounts in the following paths: %v", dstPath, p.AllowedMountDestinations)
}

func contains(strs []string, target string) bool {
	for _, s := range strs {
		if s == target {
			return true
		}
	}
	return false
}
