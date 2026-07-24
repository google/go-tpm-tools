package launcher

import (
	"context"
	"fmt"
	"os"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/oci"
	"github.com/google/go-tpm-tools/cel"
	"github.com/google/go-tpm-tools/launcher/internal/gpu"
	"github.com/google/go-tpm-tools/launcher/internal/logging"
	"github.com/google/go-tpm-tools/launcher/launcherfile"
	"github.com/google/go-tpm-tools/launcher/spec"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func createOCISpecOpts(image containerd.Image, launchSpec spec.LaunchSpec, launchPolicy spec.LaunchPolicy, envs []string, listFiles func(string, string) ([]string, error), logger logging.Logger) ([]oci.SpecOpts, error) {
	var mounts []specs.Mount
	for _, lsMnt := range launchSpec.Mounts {
		mounts = append(mounts, lsMnt.SpecsMount())
	}
	mounts = appendTokenMounts(mounts)
	if launchSpec.CgroupNamespace {
		mounts = appendCgroupRw(mounts)
	}
	hostname, err := os.Hostname()
	if err != nil {
		return nil, &RetryableError{fmt.Errorf("cannot get hostname: [%w]", err)}
	}

	rlimits := []specs.POSIXRlimit{{
		Type: "RLIMIT_NOFILE",
		Hard: nofile,
		Soft: nofile,
	}}

	specOpts := []oci.SpecOpts{
		oci.WithImageConfigArgs(image, launchSpec.Cmd),
		oci.WithEnv(envs),
		oci.WithMounts(mounts),
		// following 4 options are here to allow the container to have
		// the host network (same effect as --net-host in ctr command)
		oci.WithHostHostsFile,
		oci.WithHostResolvconf,
		oci.WithEnv([]string{fmt.Sprintf("HOSTNAME=%s", hostname)}),
		oci.WithAddedCapabilities(launchSpec.AddedCapabilities),
		withRlimits(rlimits),
		withOOMScoreAdj(defaultOOMScore),
	}

	// If we use non-root container, we enable both the user and network namespaces.
	// Otherwise, we use host network without enabling the namespaces.
	if launchPolicy.NonrootContainer {
		specOpts = append(specOpts,
			oci.WithUserNamespace(
				[]specs.LinuxIDMapping{{ContainerID: 0, HostID: hostUIDBegin, Size: userNSSize}},
				[]specs.LinuxIDMapping{{ContainerID: 0, HostID: hostGIDBegin, Size: userNSSize}},
			),
		)
	} else {
		specOpts = append(specOpts, oci.WithHostNamespace(specs.NetworkNamespace))
	}

	if launchSpec.DevShmSize != 0 {
		specOpts = append(specOpts, oci.WithDevShmSize(launchSpec.DevShmSize))
	}

	var cgroupOpts []oci.SpecOpts
	if launchSpec.CgroupNamespace {
		cgroupOpts = []oci.SpecOpts{
			oci.WithNamespacedCgroup(),
			oci.WithLinuxNamespace(specs.LinuxNamespace{Type: specs.CgroupNamespace}),
		}
	}
	specOpts = append(specOpts, cgroupOpts...)

	if launchSpec.InstallGpuDriver {
		gpuMounts := []specs.Mount{
			{
				Type:        "volume",
				Source:      fmt.Sprintf("%s/lib64", gpu.InstallationHostDir),
				Destination: fmt.Sprintf("%s/lib64", gpu.InstallationContainerDir),
				Options:     []string{"rbind", "rw"},
			}, {
				Type:        "volume",
				Source:      fmt.Sprintf("%s/bin", gpu.InstallationHostDir),
				Destination: fmt.Sprintf("%s/bin", gpu.InstallationContainerDir),
				Options:     []string{"rbind", "rw"},
			},
		}
		if launchSpec.Experiments.BcMode {
			gpuMounts = []specs.Mount{
				{
					Type:        "volume",
					Source:      fmt.Sprintf("%s/lib64", gpu.BuiltInInstallation595_58_03HostDir),
					Destination: fmt.Sprintf("%s/lib64", gpu.InstallationContainerDir),
					Options:     []string{"rbind", "rw"},
				}, {
					Type:        "volume",
					Source:      fmt.Sprintf("%s/bin", gpu.BuiltInInstallation595_58_03HostDir),
					Destination: fmt.Sprintf("%s/bin", gpu.InstallationContainerDir),
					Options:     []string{"rbind", "rw"},
				},
			}
		}

		specOpts = append(specOpts, oci.WithMounts(gpuMounts))

		// /dev/nvidia-caps/* will not be listed here and will not be passed to
		// the container workload
		//
		// following devices should be listed:
		// /dev/nvidiactl
		// /dev/nvidia-uvm
		// /dev/nvidia-uvm-tools
		// /dev/nvidia{0,1,2,...}
		// /dev/nvidia-modeset
		gpuDeviceFiles, err := listFiles("/dev", "nvidia")
		if err != nil {
			return nil, fmt.Errorf("failed to list nvidia devices: [%w]", err)
		}

		for _, deviceFile := range gpuDeviceFiles {
			logger.Info(fmt.Sprintf("Detected nvidia device : %s", deviceFile))
			specOpts = append(specOpts, oci.WithDevices(deviceFile, deviceFile, "crw-rw-rw-"))
		}
	}

	return specOpts, nil
}

// formatEnvVars formats the environment variables to the oci format
func formatEnvVars(envVars []spec.EnvVar) ([]string, error) {
	var result []string
	for _, envVar := range envVars {
		ociFormat, err := cel.FormatEnvVar(envVar.Name, envVar.Value)
		if err != nil {
			return nil, fmt.Errorf("failed to format env var: %v", err)
		}
		result = append(result, ociFormat)
	}
	return result, nil
}

// appendTokenMounts appends the default mount specs for the OIDC token
func appendTokenMounts(mounts []specs.Mount) []specs.Mount {
	m := specs.Mount{}
	m.Destination = launcherfile.ContainerRuntimeMountPath
	m.Type = "bind"
	m.Source = launcherfile.HostTmpPath
	m.Options = []string{"rbind", "ro"}

	return append(mounts, m)
}

// withRlimits sets the rlimit (like the max file descriptor) for the container process
func withRlimits(rlimits []specs.POSIXRlimit) oci.SpecOpts {
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
		s.Process.Rlimits = rlimits
		return nil
	}
}

// Set the container process's OOM score.
func withOOMScoreAdj(oomScore int) oci.SpecOpts {
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
		s.Process.OOMScoreAdj = &oomScore
		return nil
	}
}

// appendCgroupRw mount maps a cgroup as read-write.
func appendCgroupRw(mounts []specs.Mount) []specs.Mount {
	m := specs.Mount{
		Destination: "/sys/fs/cgroup",
		Type:        "cgroup",
		Source:      "cgroup",
		Options:     []string{"rw", "nosuid", "noexec", "nodev"},
	}

	return append(mounts, m)
}
