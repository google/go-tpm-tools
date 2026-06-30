// Package spec contains definition of some basic container launch specs needed to
// launch a container, provided by the operator.
package spec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/compute/metadata"
	"github.com/cenkalti/backoff/v4"

	"github.com/containerd/containerd/v2/pkg/cap"
	"github.com/google/go-tpm-tools/cel"
	"github.com/google/go-tpm-tools/launcher/internal/experiments"
	"github.com/google/go-tpm-tools/launcher/internal/launchermount"
	"github.com/google/go-tpm-tools/launcher/internal/logging"
	"github.com/google/go-tpm-tools/launcher/launcherfile"
	"github.com/google/go-tpm-tools/verifier"
	"github.com/google/go-tpm-tools/verifier/util"

	"gopkg.in/yaml.v3"
)

// MaxInt64 is the maximum value of a signed int64.
const MaxInt64 = 9223372036854775807

// RestartPolicy is the enum for the container restart policy.
type RestartPolicy string

// ContainerType specifies the role of the container
type ContainerType string

// Container type constants
const (
	MainContainer			ContainerType = "main"
	SidecarContainer 	ContainerType = "sidecar"
)

// VolumeMount defines a mount point for a container as specified in the YAML.
type VolumeMount struct {
	Type        string `yaml:"type"`
	Source      string `yaml:"source"`
	Destination string `yaml:"destination"`
	Size        string `yaml:"size,omitempty"` // Enabled size support
}

// ContainerPort defines a port mapping for a container.
type ContainerPort struct {
	ContainerPort int    `yaml:"containerPort"`
	Protocol      string `yaml:"protocol"` // e.g., "tcp", "udp"
	HostPort      int    `yaml:"hostPort,omitempty"`
}


func (p RestartPolicy) isValid() error {
	switch p {
	case Always, OnFailure, Never:
		return nil
	}
	return fmt.Errorf("invalid restart policy: %s", p)
}

// Restart Policy enum values.
const (
	Always    RestartPolicy = "Always"
	OnFailure RestartPolicy = "OnFailure"
	Never     RestartPolicy = "Never"
	// experimentDataFile defines where the experiment sync output data is expected to be.
	experimentDataFile = "experiment_data"
	// binaryPath contains the path to the experiments binary.
	binaryPath = "/usr/share/oem/confidential_space/confidential_space_experiments"
)

// LogRedirectLocation specifies the workload logging redirect location.
type LogRedirectLocation string

func (l LogRedirectLocation) isValid() error {
	switch l {
	case Everywhere, CloudLogging, Serial, Nowhere:
		return nil
	}
	return fmt.Errorf("invalid logging redirect location %s, expect one of %s", l,
		[]LogRedirectLocation{Everywhere, CloudLogging, Serial, Nowhere})
}

func (l LogRedirectLocation) enabled() bool {
	return l != Nowhere
}

// LogRedirectLocation acceptable values.
const (
	Everywhere   LogRedirectLocation = "true"
	CloudLogging LogRedirectLocation = "cloud_logging"
	Serial       LogRedirectLocation = "serial"
	Nowhere      LogRedirectLocation = "false"
)

// Metadata variable names.
const (
	fakeVerifierKey            = "test-fake-verifier"
	singleImageKey             = "tee-image-reference"
	multiContainerKey          = "tee-container-spec"
	signedImageRepos           = "tee-signed-image-repos"
	restartPolicyKey           = "tee-restart-policy"
	cmdKey                     = "tee-cmd"
	envKeyPrefix               = "tee-env-"
	impersonateServiceAccounts = "tee-impersonate-service-accounts"
	logRedirectKey             = "tee-container-log-redirect"
	memoryMonitoringEnable     = "tee-monitoring-memory-enable"
	monitoringEnable           = "tee-monitoring-enable"
	devShmSizeKey              = "tee-dev-shm-size-kb"
	mountKey                   = "tee-mount"
	itaRegion                  = "ita-region"
	itaKey                     = "ita-api-key"
	addedCaps                  = "tee-added-capabilities"
	cgroupNS                   = "tee-cgroup-ns"
	gcaServiceEnv              = "gca-service-env"
	installGpuDriver           = "tee-install-gpu-driver"
	disableGcaRefreshKey       = "tee-disable-gca-refresh"
)

const (
	instanceAttributesQuery = "instance/attributes/?recursive=true"
)

var gcaInstances = map[string]string{
	"prod":     "https://confidentialcomputing.googleapis.com",
	"autopush": "https://autopush-confidentialcomputing.sandbox.googleapis.com",
	"staging":  "https://staging-confidentialcomputing.sandbox.googleapis.com",
}

var errImageRefNotSpecified = fmt.Errorf("%s is not specified in the custom metadata", singleImageKey)

// EnvVar represent a single environment variable key/value pair.
type EnvVar struct {
	Name  string `yaml:"name" json:"name"`
	Value string `yaml:"value" json:"value"`
}

// ContainerSpec contains the specification for a single container within the pod.
type ContainerSpec struct {
	Name              string          `yaml:"name"`
	ImageRef          string          `yaml:"image"`
	ContainerType     ContainerType   `yaml:"containerType"` // main vs sidecar
	RestartPolicy     RestartPolicy   `yaml:"restartPolicy"` // Container-level rule
	Cmd               []string        `yaml:"cmd,omitempty"`
	Envs              []EnvVar        `yaml:"envs,omitempty"`
	VolumeMounts      []VolumeMount   `yaml:"volumeMounts,omitempty"`
	Ports             []ContainerPort `yaml:"ports,omitempty"`
	AddedCapabilities []string        `yaml:"addedCapabilities,omitempty"`
	// Internal representation, not directly from YAML:
	Mounts []launchermount.Mount `yaml:"-"` // Parsed from VolumeMounts
}

// LaunchSpec contains specification set by the operator who wants to
// launch a container.
type LaunchSpec struct {
	Experiments         experiments.Experiments
	FakeVerifierEnabled bool

	// VM-level configuration
	GcaAddress                 string
	ImpersonateServiceAccounts []string
	ProjectID                  string
	Region                     string
	Hardened                   bool
	MonitoringEnabled          MonitoringType
	LogRedirect                LogRedirectLocation
	ITAConfig                  verifier.ITAConfig
	DevShmSize                 int64 // DevShmSize is specified in kiB.
	CgroupNamespace            bool
	InstallGpuDriver           bool
	DisableGcaRefresh          bool
	SignedImageRepos           []string

	//New: Multi-container support
	Containers                 []ContainerSpec
	VMRestartPolicy            RestartPolicy

	//DEPRECATED: Legacy single-container fields(keep for backward compatability during refactoring)
	ImageRef                   string
	RestartPolicy              RestartPolicy
	Cmd                        []string
	Envs                       []EnvVar
	Mounts                     []launchermount.Mount
	AddedCapabilities          []string
}

func parseVolumeMount(vm VolumeMount) (launchermount.Mount, error) {
	mountMap := map[string]string{
		launchermount.TypeKey:        vm.Type,
		launchermount.SourceKey:      vm.Source,
		launchermount.DestinationKey: vm.Destination,
	}
	if vm.Size != "" {
		mountMap[launchermount.SizeKey] = vm.Size
	}

	switch vm.Type {
	case launchermount.TypeTmpfs:
		return launchermount.CreateTmpfsMount(mountMap)
	default:
		return nil, fmt.Errorf("unknown mount type %q, only %q is supported", vm.Type, launchermount.TypeTmpfs)
	}
}


//parseMultiContainerSpec parses the YAML representation of the multi-container spec
// and performs basic validation and volume mount conversion.
func parseMultiContainerSpec(specYaml string) ([]ContainerSpec, RestartPolicy, error) {
	var mcSpec struct {
		VMRestartPolicy RestartPolicy `yaml:"vmRestartPolicy"`
		Containers      []ContainerSpec `yaml:"containers"`
	}

	if err := yaml.Unmarshal([]byte(specYaml), &mcSpec); err != nil {
		return nil, "", fmt.Errorf("failed to parse YAML: %w", err)
	}

	//validate and map fields for each container 
	for i := range mcSpec.Containers {
		c := &mcSpec.Containers[i]
		if c.Name == "" {
			return nil, "", fmt.Errorf("container at index %d is missing a name", i)
		}
		if c.ImageRef == "" {
			return nil, "", fmt.Errorf("container %q is missing an image reference", c.Name)
		}

		// Convert VolumeMounts to internal Mounts
		for _, vm := range c.VolumeMounts {
			mnt, err := parseVolumeMount(vm)
			if err != nil {
				return nil, "", fmt.Errorf("failed to volume mount for container %q: %w", c.Name, err)
			}

			c.Mounts = append(c.Mounts, mnt)
		}
	}

	return mcSpec.Containers, mcSpec.VMRestartPolicy, nil
}

// UnmarshalJSON unmarshals an instance attributes list in JSON format from the metadata
// server set by an operator to a LaunchSpec.
// This method expects experiments to be set on the LaunchSpec before being called.
func (s *LaunchSpec) UnmarshalJSON(b []byte) error {
	var unmarshaledMap map[string]string
	if err := json.Unmarshal(b, &unmarshaledMap); err != nil {
		return err
	}

	// -------------------------------------------------------------
	// 1. VM-level Initial Flag Parsing (Top-level)
	// -------------------------------------------------------------
	if val, ok := unmarshaledMap[fakeVerifierKey]; ok && val != "" {
		var err error
		if s.FakeVerifierEnabled, err = strconv.ParseBool(val); err != nil {
			return fmt.Errorf("invalid value for %v (not a boolean): %w", fakeVerifierKey, err)
		}
	}

	if val, ok := unmarshaledMap[installGpuDriver]; ok && val != "" {
		if boolValue, err := strconv.ParseBool(val); err == nil {
			s.InstallGpuDriver = boolValue
		}
	}

	// -------------------------------------------------------------
	// 2. Container-Specific Parsing (Branching)
	// -------------------------------------------------------------
	if specYAML, ok := unmarshaledMap[multiContainerKey]; ok && specYAML != "" {
		// Multi-container parsing path 
		containers, vmRestartPolicy, err := parseMultiContainerSpec(specYAML)
		if err != nil {
			return err
		}

		s.Containers = containers
		s.VMRestartPolicy = vmRestartPolicy
		if s.VMRestartPolicy == "" {
			s.VMRestartPolicy = Never
		}
		if err := s.VMRestartPolicy.isValid(); err != nil{
			return err
		}

		//Normalize: Populate legacy fields from the main container for compatibility
		if len(s.Containers) > 0 {
			var mainContainer *ContainerSpec
			for i := range s.Containers {
				if s.Containers[i].ContainerType == MainContainer {
					mainContainer = &s.Containers[i]
					break
				}
			}

			if mainContainer == nil {
				mainContainer = &s.Containers[0]
			}

			s.ImageRef = mainContainer.ImageRef
			s.Cmd = mainContainer.Cmd
			s.Envs = mainContainer.Envs
			s.RestartPolicy = s.VMRestartPolicy
			s.Mounts = mainContainer.Mounts
			s.AddedCapabilities = mainContainer.AddedCapabilities
		}
	} else {
		// Single-container parsing path (Legacy Fallback)
		s.ImageRef = unmarshaledMap[singleImageKey]
		if s.ImageRef == "" {
			return errImageRefNotSpecified
		}
	
		s.RestartPolicy = RestartPolicy(unmarshaledMap[restartPolicyKey])
		// Set the default restart policy to "Never" for now.
		if s.RestartPolicy == "" {
			s.RestartPolicy = Never
		}
		if err := s.RestartPolicy.isValid(); err != nil {
			return err
		}
		s.VMRestartPolicy = s.RestartPolicy

		// Populate cmd override.
		if val, ok := unmarshaledMap[cmdKey]; ok && val != "" {
			if err := json.Unmarshal([]byte(val), &s.Cmd); err != nil {
				return err
			}
		}

		// Populate all env vars(tee-env-*).
		for k, v := range unmarshaledMap {
			if strings.HasPrefix(k, envKeyPrefix) {
				s.Envs = append(s.Envs, EnvVar{strings.TrimPrefix(k, envKeyPrefix), v})
			}
		}
		
		// Populate mount override(tee-mount).
		// https://cloud.google.com/compute/docs/disks/set-persistent-device-name-in-linux-vm
		// https://cloud.google.com/compute/docs/disks/add-local-ssd
		if val, ok := unmarshaledMap[mountKey]; ok && val != "" {
			mounts := strings.Split(val, ";")
			for _, mount := range mounts {
				specMnt, err := processMount(mount)
				if err != nil {
					return err
				}
				s.Mounts = append(s.Mounts, specMnt)
			}
		}

		// Populate capabilities override(tee-added-capabilities).
		if val, ok := unmarshaledMap[addedCaps]; ok && val != "" {
			if err := json.Unmarshal([]byte(val), &s.AddedCapabilities); err != nil {
				return err
			}
		}

		//Normalize: Populate s.Containers with the legacy container spec
		s.Containers = []ContainerSpec{
			{
				Name: 				"main",
				ImageRef: 				s.ImageRef,
				ContainerType: 		MainContainer,
				RestartPolicy: 		s.RestartPolicy,
				Cmd: 					s.Cmd,
				Envs: 					s.Envs,
				Mounts: 				s.Mounts,
				AddedCapabilities: 	s.AddedCapabilities,
			},
		}
	}

	// -------------------------------------------------------------
	// 3. VM-level Shared Configuration Parsing
	// -------------------------------------------------------------
	if val, ok := unmarshaledMap[impersonateServiceAccounts]; ok && val != "" {
		impersonateAccounts := strings.Split(val, ",")
		s.ImpersonateServiceAccounts = append(s.ImpersonateServiceAccounts, impersonateAccounts...)
	}

	if val, ok := unmarshaledMap[signedImageRepos]; ok && val != "" {
		imageRepos := strings.Split(val, ",")
		s.SignedImageRepos = append(s.SignedImageRepos, imageRepos...)
	}

	memVal, memOk := unmarshaledMap[memoryMonitoringEnable]
	monVal, monOk := unmarshaledMap[monitoringEnable]

	if memOk && monOk {
		return fmt.Errorf("both %v and %v are specified, only one is permitted", memoryMonitoringEnable, monitoringEnable)
	} else if memOk {
		// If value is empty, treat as the default.
		if memVal == "" {
			s.MonitoringEnabled = None
		} else {
			boolValue, err := strconv.ParseBool(memVal)
			if err != nil {
				return fmt.Errorf("invalid value for %v (not a boolean): %v", memoryMonitoringEnable, err)
			}

			if boolValue {
				s.MonitoringEnabled = MemoryOnly
			} else {
				s.MonitoringEnabled = None
			}
		}
	} else if monOk {
		// If value is empty, treat as the default.
		if monVal == "" {
			s.MonitoringEnabled = None
		} else {
			var err error
			s.MonitoringEnabled, err = toMonitoringType(monVal)
			if err != nil {
				return err
			}
		}
	}

	s.LogRedirect = LogRedirectLocation(unmarshaledMap[logRedirectKey])
	// Default log redirect location is Nowhere ("false").
	if s.LogRedirect == "" {
		s.LogRedirect = Nowhere
	}
	if err := s.LogRedirect.isValid(); err != nil {
		return err
	}

	if err := s.setAttestationServiceVars(unmarshaledMap); err != nil {
		return err
	}

	// Populate /dev/shm size override.
	if val, ok := unmarshaledMap[devShmSizeKey]; ok && val != "" {
		size, err := strconv.ParseUint(val, 10, 64)
		if err != nil {
			return fmt.Errorf("failed to convert %v into uint64, got: %v", devShmSizeKey, val)
		}
		s.DevShmSize = int64(size)
	}

	if s.Experiments.EnableItaVerifier {
		itaRegionVal, itaRegionOK := unmarshaledMap[itaRegion]
		itaKeyVal, itaKeyOK := unmarshaledMap[itaKey]

		// If key and region are both not in the map, do not set up ITA config.
		if itaRegionOK != itaKeyOK {
			return fmt.Errorf("ITA fields %s and %s must both be provided and non-empty", itaRegion, itaKey)
		}

		s.ITAConfig = verifier.ITAConfig{
			ITARegion: itaRegionVal,
			ITAKey:    itaKeyVal,
		}
	}

	// Populate cgroup ns.
	cgroupSetting, ok := unmarshaledMap[cgroupNS]
	if ok {
		cgroupOn, err := strconv.ParseBool(cgroupSetting)
		if err != nil {
			return fmt.Errorf("invalid value for %v (not a boolean): %v", cgroupNS, err)
		}
		if cgroupOn {
			s.CgroupNamespace = true
		}
	}

	if val, ok := unmarshaledMap[disableGcaRefreshKey]; ok && val != "" {
		var err error
		if s.DisableGcaRefresh, err = strconv.ParseBool(val); err != nil {
			return fmt.Errorf("invalid value for %v (not a boolean): %w", disableGcaRefreshKey, err)
		}
	}

	return nil
}

func (s *LaunchSpec) setAttestationServiceVars(unmarshaledMap map[string]string) error {
	if gcaServiceEnv, ok := unmarshaledMap[gcaServiceEnv]; ok {
		v, ok := gcaInstances[strings.ToLower(gcaServiceEnv)]
		if !ok {
			return fmt.Errorf("the gca service env is not within the allowlist, want %+v, got %s", gcaInstances, gcaServiceEnv)
		}
		s.GcaAddress = v
	}

	return nil
}

// LogFriendly creates a copy of the spec that is safe to log by censoring
func (s *LaunchSpec) LogFriendly() LaunchSpec {
	safeSpec := *s
	safeSpec.ITAConfig.ITAKey = strings.Repeat("*", len(s.ITAConfig.ITAKey))

	var safeEnvs []EnvVar
	for _, envVar := range s.Envs {
		if envVar.Value != "" {
			safeEnvs = append(safeEnvs, EnvVar{envVar.Name, "[REDACTED]"})
		} else {
			safeEnvs = append(safeEnvs, envVar)
		}
	}
	safeSpec.Envs = safeEnvs

	if len(s.Containers) > 0 {
		safeContainers := make([]ContainerSpec, len(s.Containers))
		for i, c := range s.Containers {
			safeContainer := c
			var safeContainerEnvs []EnvVar
			for _, envVar := range c.Envs {
				if envVar.Value != "" {
					safeContainerEnvs = append(safeContainerEnvs, EnvVar{envVar.Name, "[REDACTED]"})
				} else {
					safeContainerEnvs = append(safeContainerEnvs, envVar)
				}
			}
			safeContainer.Envs = safeContainerEnvs
			safeContainers[i] = safeContainer
		}
		safeSpec.Containers = safeContainers
	}

	return safeSpec
}

// GetLaunchSpec takes in a metadata server client, reads and parse operator's
// input to the GCE instance custom metadata and return a LaunchSpec.
// ImageRef (tee-image-reference) is required, will return an error if
// ImageRef is not presented in the metadata.
func GetLaunchSpec(ctx context.Context, logger logging.Logger, client *metadata.Client) (LaunchSpec, error) {
	data, err := client.GetWithContext(ctx, instanceAttributesQuery)
	if err != nil {
		return LaunchSpec{}, err
	}

	spec := &LaunchSpec{}
	spec.Experiments = fetchExperiments(logger)
	if err := spec.UnmarshalJSON([]byte(data)); err != nil {
		return LaunchSpec{}, err
	}

	var errs []error
	// Validate legacy mounts
	for _, mnt := range spec.Mounts {
		if err := validateMount(mnt); err != nil {
			errs = append(errs, err)
		}
	}
	// Validate container mounts
	for _, c := range spec.Containers {
		for _, mnt := range c.Mounts {
			if err := validateMount(mnt); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if len(errs) != 0 {
		return LaunchSpec{}, fmt.Errorf("failed to validate mounts: %v", errors.Join(errs...))
	}

	if !(spec.Experiments.EnableB200DriverInstallation || spec.Experiments.EnableH100DriverInstallation) && spec.InstallGpuDriver {
		return LaunchSpec{}, fmt.Errorf("GPU Driver installation is not supported")
	}

	if err := validateMemorySizeKb(uint64(spec.DevShmSize)); err != nil {
		return LaunchSpec{}, fmt.Errorf("failed to validate /dev/shm size: %v", err)
	}

	// Validate legacy capabilities
	if err := validateAddedCapsAllowed(spec.AddedCapabilities); err != nil {
		return LaunchSpec{}, fmt.Errorf("failed to validate added capabilities: %v", err)
	}
	// Validate container capabilities
	for _, c := range spec.Containers {
		if err := validateAddedCapsAllowed(c.AddedCapabilities); err != nil {
			return LaunchSpec{}, fmt.Errorf("failed to validate added capabilities for container %q: %v", c.Name, err)
		}
	}

	spec.ProjectID, err = client.ProjectIDWithContext(ctx)
	if err != nil {
		return LaunchSpec{}, fmt.Errorf("failed to retrieve projectID from MDS: %v", err)
	}

	spec.Region, err = util.GetRegion(client)
	if err != nil {
		return LaunchSpec{}, err
	}

	kernelCmd, err := readCmdline()
	if err != nil {
		return LaunchSpec{}, err
	}
	spec.Hardened = isHardened(kernelCmd)

	return *spec, nil
}

func isHardened(kernelCmd string) bool {
	for _, arg := range strings.Fields(kernelCmd) {
		if arg == "confidential-space.hardened=true" {
			return true
		}
	}
	return false
}

func fetchExperiments(logger logging.Logger) experiments.Experiments {
	experimentsFile := path.Join(launcherfile.HostTmpPath, experimentDataFile)

	var e experiments.Experiments
	// If a pre-loaded experiments file already exists (e.g. for VG/BC modes),
	// skip the sync phase and load it directly.
	if _, err := os.Stat(experimentsFile); err == nil {
		logger.Info("Pre-loaded experiments file found; skipping sync.")
		var err error
		e, err = experiments.New(experimentsFile)
		if err != nil {
			logger.Error(fmt.Sprintf("failed to read pre-loaded experiment file: %v\n", err))
		}
		return e
	}

	args := fmt.Sprintf("-output=%s", experimentsFile)
	if err := backoff.Retry(func() error {
		if err := exec.Command(binaryPath, args).Run(); err != nil {
			logger.Error(fmt.Sprintf("failure during experiment sync: %v\n", err))
		}
		var err error
		e, err = experiments.New(experimentsFile)
		if err != nil {
			logger.Error(fmt.Sprintf("failed to read experiment file: %v\n", err))
		}
		// This is expected to be true if experiment sync is successful.
		if !e.EnableTestFeatureForImage {
			return fmt.Errorf("experiments synced but EnableTestFeatureForImage is false")
		}
		return nil
	}, experimentSyncBackoffPolicy()); err != nil {
		logger.Error(fmt.Sprintf("experiment retrieval failed after retries: %v\n", err))
		// Do not fail if experiment retrieval fails.
	}
	return e
}

func experimentSyncBackoffPolicy() backoff.BackOff {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = 2 * time.Second
	b.MaxInterval = 8 * time.Second
	b.Multiplier = 2.0
	b.RandomizationFactor = 0.1
	return backoff.WithMaxRetries(b, 3)
}

func processMount(singleMount string) (launchermount.Mount, error) {
	mntConfig := make(map[string]string)
	var mntType string
	mountOpts := strings.Split(singleMount, ",")
	for _, mountOpt := range mountOpts {
		name, val, err := cel.ParseEnvVar(mountOpt)
		if err != nil {
			return nil, fmt.Errorf("failed to parse mount option: %w", err)
		}
		switch name {
		case launchermount.TypeKey:
			mntType = val
		case launchermount.SourceKey:
		case launchermount.DestinationKey:
		case launchermount.SizeKey:
		default:
			return nil, fmt.Errorf("found unknown mount option: %v, expect keys of %v", mountOpt, launchermount.AllMountKeys)
		}
		mntConfig[name] = val
	}

	switch mntType {
	case launchermount.TypeTmpfs:
		return launchermount.CreateTmpfsMount(mntConfig)
	default:
		return nil, fmt.Errorf("found unknown or unspecified mount type: %v, expect one of types [%v]", mountOpts, launchermount.TypeTmpfs)
	}
}

func validateMount(mnt launchermount.Mount) error {
	switch v := mnt.(type) {
	case launchermount.TmpfsMount:
		return validateMemorySizeKb(v.Size / 1024)
	default:
		return fmt.Errorf("got unknown mount type: %T", v)
	}
}

// Ensures that system free memory is larger than the specified memory size.
func validateMemorySizeKb(memSize uint64) error {
	freeMem, err := getLinuxFreeMem()
	if err != nil {
		return fmt.Errorf("failed to get free memory: %v", err)
	}
	if memSize > freeMem {
		return fmt.Errorf("got a /dev/shm size (%v) larger than free memory (%v) kB", memSize, freeMem)
	}
	if memSize > MaxInt64 {
		return fmt.Errorf("got a size greater than max int64: %v", memSize)
	}
	return nil
}

func getLinuxFreeMem() (uint64, error) {
	meminfo, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, fmt.Errorf("failed to read /proc/meminfo: %w", err)
	}
	for _, memtype := range strings.Split(string(meminfo), "\n") {
		if !strings.Contains(memtype, "MemFree") {
			continue
		}
		split := strings.Fields(memtype)
		if len(split) != 3 {
			return 0, fmt.Errorf("found invalid MemInfo entry: got: %v, expected format: MemFree:        <amount> kB", memtype)
		}
		if split[2] != "kB" {
			return 0, fmt.Errorf("found invalid MemInfo entry: got: %v, expected format: MemFree:        <amount> kB", memtype)
		}
		freeMem, err := strconv.ParseUint(split[1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("failed to convert MemFree to uint64: %v", memtype)
		}
		return freeMem, nil
	}
	return 0, fmt.Errorf("failed to find MemFree in /proc/meminfo: %v", string(meminfo))
}

func readCmdline() (string, error) {
	kernelCmd, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return "", err
	}
	return string(kernelCmd), nil
}

func validateAddedCapsAllowed(addedCaps []string) error {
	caps, err := getCurrCaps()
	if err != nil {
		return fmt.Errorf("failed to fetch current capabilities: %v", err)
	}
	var notInCurr []string
	for _, addedCap := range addedCaps {
		if _, ok := caps[addedCap]; !ok {
			notInCurr = append(notInCurr, addedCap)
		}
	}
	if len(notInCurr) != 0 {
		return fmt.Errorf("received added capabilities (%v) not allowed by current capabilities", notInCurr)

	}
	return nil
}

func getCurrCaps() (map[string]bool, error) {
	caps, err := cap.Current()
	if err != nil {
		return nil, err
	}
	capsMap := make(map[string]bool, len(caps))
	for _, cap := range caps {
		capsMap[cap] = true
	}
	return capsMap, nil
}
