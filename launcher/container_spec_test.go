package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/oci"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-tpm-tools/launcher/internal/experiments"
	"github.com/google/go-tpm-tools/launcher/internal/launchermount"
	"github.com/google/go-tpm-tools/launcher/internal/logging"
	"github.com/google/go-tpm-tools/launcher/spec"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

type mockMount struct {
	specsMount specs.Mount
}

func (m mockMount) SpecsMount() specs.Mount {
	return m.specsMount
}

func (m mockMount) Mountpoint() string {
	return m.specsMount.Destination
}

func createFakeImage(labels map[string]string, entrypoint, cmd []string) *fakeImage {
	ic := v1.Image{
		Config: v1.ImageConfig{
			Labels:     labels,
			Entrypoint: entrypoint,
			Cmd:        cmd,
		},
	}
	b, _ := json.Marshal(ic)
	return &fakeImage{
		name:         "test-image",
		id:           "test-id",
		digest:       "sha256:12345",
		contentStore: &fakeContentStore{blob: b},
	}
}

func dummyListFiles(_, _ string) ([]string, error) {
	return nil, nil
}

func getFuncName(i any) string {
	return runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
}

// createDefaultLinuxNamespaces returns a default set of namespaces similar to containerd's default template.
func createDefaultLinuxNamespaces() []specs.LinuxNamespace {
	return []specs.LinuxNamespace{
		{Type: specs.PIDNamespace, Path: "/proc/1/ns/pid"},
		{Type: specs.NetworkNamespace, Path: "/proc/1/ns/net"},
		{Type: specs.IPCNamespace, Path: "/proc/1/ns/ipc"},
		{Type: specs.UTSNamespace, Path: "/proc/1/ns/uts"},
		{Type: specs.MountNamespace, Path: "/proc/1/ns/mnt"},
	}
}

func applySpecOptsToSpec(ctx context.Context, specOpts []oci.SpecOpts) (specs.Spec, error) {
	gotSpec := oci.Spec{
		Mounts: []specs.Mount{
			{Destination: "/dev/shm", Type: "tmpfs", Source: "shm"},
		},
		Linux: &specs.Linux{
			Namespaces: createDefaultLinuxNamespaces(),
			Resources:  &specs.LinuxResources{},
		},
		Process: &specs.Process{},
	}
	dummyContainer := containers.Container{ID: "dummy"}
	for _, opt := range specOpts[1:] { // Skip WithImageConfigArgs
		if err := opt(ctx, nil, &dummyContainer, &gotSpec); err != nil {
			return gotSpec, err
		}
	}
	return gotSpec, nil
}

func TestCreateOCISpecOpts_ProcessEnv(t *testing.T) {
	ctx := namespaces.WithNamespace(context.Background(), "default")
	logger := &fakeLogger{}
	img := createFakeImage(map[string]string{"foo": "bar"}, []string{"/bin/entrypoint"}, []string{"default", "args"})
	envs := []string{"ENV_VAR_1=value1", "ENV_VAR_2=value2"}

	specOpts, err := createOCISpecOpts(img, spec.LaunchSpec{}, envs, dummyListFiles, logger)
	if err != nil {
		t.Fatalf("createOCISpecOpts failed: %v", err)
	}

	gotSpec, err := applySpecOptsToSpec(ctx, specOpts)
	if err != nil {
		t.Fatalf("failed to apply spec option: %v", err)
	}

	hasEnv1, hasEnv2, hasHostname := false, false, false
	for _, env := range gotSpec.Process.Env {
		if env == "ENV_VAR_1=value1" {
			hasEnv1 = true
		}
		if env == "ENV_VAR_2=value2" {
			hasEnv2 = true
		}
		if strings.HasPrefix(env, "HOSTNAME=") {
			hasHostname = true
		}
	}
	if !hasEnv1 || !hasEnv2 || !hasHostname {
		t.Errorf("Env variables not set correctly: envs=%v", gotSpec.Process.Env)
	}
}

func TestCreateOCISpecOpts_Mounts(t *testing.T) {
	ctx := namespaces.WithNamespace(context.Background(), "default")
	logger := &fakeLogger{}
	img := createFakeImage(nil, nil, nil)

	ls := spec.LaunchSpec{
		Mounts: []launchermount.Mount{
			mockMount{
				specsMount: specs.Mount{
					Source:      "/host/path",
					Destination: "/container/path",
					Type:        "bind",
				},
			},
		},
	}

	specOpts, err := createOCISpecOpts(img, ls, nil, dummyListFiles, logger)
	if err != nil {
		t.Fatalf("createOCISpecOpts failed: %v", err)
	}

	gotSpec, err := applySpecOptsToSpec(ctx, specOpts)
	if err != nil {
		t.Fatalf("failed to apply spec option: %v", err)
	}

	foundOperatorMount, foundTokenMount := false, false
	for _, mnt := range gotSpec.Mounts {
		if mnt.Source == "/host/path" && mnt.Destination == "/container/path" {
			foundOperatorMount = true
		}
		if strings.Contains(mnt.Destination, "container_launcher") {
			for _, opt := range mnt.Options {
				if opt == "ro" {
					foundTokenMount = true
				}
			}
		}
	}
	if !foundOperatorMount {
		t.Errorf("Operator mount not found in spec: mounts=%v", gotSpec.Mounts)
	}
	if !foundTokenMount {
		t.Errorf("Default OIDC token mount (container_launcher, ro) not found in spec: mounts=%v", gotSpec.Mounts)
	}
}

func TestCreateOCISpecOpts_Rlimits(t *testing.T) {
	ctx := namespaces.WithNamespace(context.Background(), "default")
	logger := &fakeLogger{}
	img := createFakeImage(nil, nil, nil)

	specOpts, err := createOCISpecOpts(img, spec.LaunchSpec{}, nil, dummyListFiles, logger)
	if err != nil {
		t.Fatalf("createOCISpecOpts failed: %v", err)
	}

	gotSpec, err := applySpecOptsToSpec(ctx, specOpts)
	if err != nil {
		t.Fatalf("failed to apply spec option: %v", err)
	}

	foundLimit := false
	for _, limit := range gotSpec.Process.Rlimits {
		if limit.Type == "RLIMIT_NOFILE" && limit.Hard == nofile && limit.Soft == nofile {
			foundLimit = true
		}
	}
	if !foundLimit {
		t.Errorf("File descriptor limits not applied correctly: %v", gotSpec.Process.Rlimits)
	}
}

func TestCreateOCISpecOpts_Namespaces(t *testing.T) {
	ctx := namespaces.WithNamespace(context.Background(), "default")
	logger := &fakeLogger{}
	img := createFakeImage(nil, nil, nil)

	specOpts, err := createOCISpecOpts(img, spec.LaunchSpec{}, nil, dummyListFiles, logger)
	if err != nil {
		t.Fatalf("createOCISpecOpts failed: %v", err)
	}

	gotSpec, err := applySpecOptsToSpec(ctx, specOpts)
	if err != nil {
		t.Fatalf("failed to apply spec option: %v", err)
	}

	foundNetNS, foundPIDNS, foundIPCNS, foundUTSNS, foundMountNS := false, false, false, false, false
	for _, ns := range gotSpec.Linux.Namespaces {
		switch ns.Type {
		case specs.NetworkNamespace:
			foundNetNS = true
		case specs.PIDNamespace:
			foundPIDNS = true
		case specs.IPCNamespace:
			foundIPCNS = true
		case specs.UTSNamespace:
			foundUTSNS = true
		case specs.MountNamespace:
			foundMountNS = true
		}
	}
	if foundNetNS {
		t.Errorf("Host network namespace sharing failed: NetworkNamespace was not removed from the spec. Namespaces: %v", gotSpec.Linux.Namespaces)
	}
	if !foundPIDNS || !foundIPCNS || !foundUTSNS || !foundMountNS {
		t.Errorf("Only NetworkNamespace should be removed for host sharing. Namespaces: %v", gotSpec.Linux.Namespaces)
	}
}

func TestCreateOCISpecOpts_Cgroups(t *testing.T) {
	ctx := namespaces.WithNamespace(context.Background(), "default")
	logger := &fakeLogger{}
	img := createFakeImage(nil, nil, nil)

	testCases := []struct {
		name            string
		cgroupNamespace bool
		wantCgroupNS    bool
	}{
		{
			name:            "cgroup namespace enabled",
			cgroupNamespace: true,
			wantCgroupNS:    true,
		},
		{
			name:            "cgroup namespace disabled (host namespace)",
			cgroupNamespace: false,
			wantCgroupNS:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ls := spec.LaunchSpec{
				CgroupNamespace: tc.cgroupNamespace,
			}
			specOpts, err := createOCISpecOpts(img, ls, nil, dummyListFiles, logger)
			if err != nil {
				t.Fatalf("createOCISpecOpts failed: %v", err)
			}

			// Verify the first option is indeed WithImageConfigArgs
			if len(specOpts) == 0 {
				t.Fatalf("specOpts is empty")
			}
			firstOptName := getFuncName(specOpts[0])
			if !strings.Contains(firstOptName, "WithImageConfigArgs") {
				t.Errorf("expected first option to be WithImageConfigArgs, got %s", firstOptName)
			}

			gotSpec := oci.Spec{
				Linux: &specs.Linux{
					Namespaces: createDefaultLinuxNamespaces(),
				},
				Process: &specs.Process{},
			}
			dummyContainer := containers.Container{ID: "dummy"}
			for _, opt := range specOpts[1:] { // Skip WithImageConfigArgs
				if err := opt(ctx, nil, &dummyContainer, &gotSpec); err != nil {
					t.Fatalf("failed to apply spec option: %v", err)
				}
			}

			foundCgroupNS := false
			if gotSpec.Linux != nil {
				for _, ns := range gotSpec.Linux.Namespaces {
					if ns.Type == specs.CgroupNamespace {
						foundCgroupNS = true
					}
				}
			}
			if foundCgroupNS != tc.wantCgroupNS {
				t.Errorf("Cgroup namespace presence mismatch: got %v, want %v", foundCgroupNS, tc.wantCgroupNS)
			}
		})
	}
}

func TestCreateOCISpecOpts_GPU(t *testing.T) {
	ctx := namespaces.WithNamespace(context.Background(), "default")
	logger := &fakeLogger{}
	img := createFakeImage(nil, nil, nil)

	// Injected mock filesystem scanner
	mockListFiles := func(dir, prefix string) ([]string, error) {
		if dir == "/dev" && prefix == "nvidia" {
			return []string{"/dev/nvidia0", "/dev/nvidiactl"}, nil
		}
		return nil, nil
	}

	ls := spec.LaunchSpec{
		InstallGpuDriver: true,
	}

	specOpts, err := createOCISpecOpts(img, ls, nil, mockListFiles, logger)
	if err != nil {
		t.Fatalf("createOCISpecOpts failed: %v", err)
	}

	// Verify the first option is indeed WithImageConfigArgs
	if len(specOpts) == 0 {
		t.Fatalf("specOpts is empty")
	}
	firstOptName := getFuncName(specOpts[0])
	if !strings.Contains(firstOptName, "WithImageConfigArgs") {
		t.Errorf("expected first option to be WithImageConfigArgs, got %s", firstOptName)
	}

	gotSpec := oci.Spec{
		Linux: &specs.Linux{
			Namespaces: createDefaultLinuxNamespaces(),
			Resources:  &specs.LinuxResources{},
		},
		Process: &specs.Process{},
	}

	// We also skip WithDevices options in tests since they run os.Stat on host paths that don't exist.
	var hasGPUDeviceOpt bool
	dummyContainer := containers.Container{ID: "dummy"}
	for _, opt := range specOpts[1:] { // Skip WithImageConfigArgs
		optName := getFuncName(opt)
		if strings.Contains(optName, "WithDevices") {
			hasGPUDeviceOpt = true
			continue // Skip executing the device stat option
		}

		if err := opt(ctx, nil, &dummyContainer, &gotSpec); err != nil {
			t.Fatalf("failed to apply spec option: %v", err)
		}
	}

	if !hasGPUDeviceOpt {
		t.Errorf("expected to find WithDevices option for GPU device mapping")
	}

	// Verify GPU library bind mounts
	foundGpuMount := false
	for _, mnt := range gotSpec.Mounts {
		if mnt.Destination == "/usr/local/nvidia/lib64" {
			foundGpuMount = true
		}
	}
	if !foundGpuMount {
		t.Errorf("GPU library mount not found in spec: %v", gotSpec.Mounts)
	}
}

func TestCreateOCISpecOpts_GPU_BCMode(t *testing.T) {
	ctx := namespaces.WithNamespace(context.Background(), "default")
	logger := &fakeLogger{}
	img := createFakeImage(nil, nil, nil)

	mockListFiles := func(dir, prefix string) ([]string, error) {
		if dir == "/dev" && prefix == "nvidia" {
			return []string{"/dev/nvidia0"}, nil
		}
		return nil, nil
	}

	ls := spec.LaunchSpec{
		InstallGpuDriver: true,
		Experiments: experiments.Experiments{
			BcMode: true,
		},
	}

	specOpts, err := createOCISpecOpts(img, ls, nil, mockListFiles, logger)
	if err != nil {
		t.Fatalf("createOCISpecOpts failed: %v", err)
	}

	gotSpec := oci.Spec{
		Linux: &specs.Linux{
			Namespaces: createDefaultLinuxNamespaces(),
			Resources:  &specs.LinuxResources{},
		},
		Process: &specs.Process{},
	}

	dummyContainer := containers.Container{ID: "dummy"}
	for _, opt := range specOpts[1:] { // Skip WithImageConfigArgs
		optName := getFuncName(opt)
		if strings.Contains(optName, "WithDevices") {
			continue // Skip executing the device stat option
		}
		if err := opt(ctx, nil, &dummyContainer, &gotSpec); err != nil {
			t.Fatalf("failed to apply spec option: %v", err)
		}
	}

	// Verify GPU library bind mounts use the pre-baked 610.57.04 path
	foundBcMount := false
	for _, mnt := range gotSpec.Mounts {
		if mnt.Source == "/opt/nvidia/610.57.04/lib64" && mnt.Destination == "/usr/local/nvidia/lib64" {
			foundBcMount = true
		}
	}
	if !foundBcMount {
		t.Errorf("Expected BC Mode GPU mount (/opt/nvidia/610.57.04/lib64 -> /usr/local/nvidia/lib64) not found in spec: %v", gotSpec.Mounts)
	}
}

func TestCreateOCISpecOpts_GPU_GB300CCMode(t *testing.T) {
	ctx := namespaces.WithNamespace(context.Background(), "default")
	logger := &fakeLogger{}
	img := createFakeImage(nil, nil, nil)

	origFind := findGB300DriverDir
	t.Cleanup(func() { findGB300DriverDir = origFind })
	findGB300DriverDir = func() (string, error) { return "/opt/nvidia/620.06", nil }
	stubFindGB300FTPMDevs(t, nil, nil)       // Do not scan the host's /dev for fTPM symlinks.
	stubFindGB300FabricSpecOpts(t, nil, nil) // Do not stat host IMEX/MNCCD paths or devices.

	mockListFiles := func(dir, prefix string) ([]string, error) {
		if dir == "/dev" && prefix == "nvidia" {
			return []string{"/dev/nvidia0"}, nil
		}
		return nil, nil
	}

	ls := spec.LaunchSpec{
		InstallGpuDriver: true,
		Experiments: experiments.Experiments{
			GB300CCMode: true,
		},
	}

	specOpts, err := createOCISpecOpts(img, ls, nil, mockListFiles, logger)
	if err != nil {
		t.Fatalf("createOCISpecOpts failed: %v", err)
	}

	gotSpec := oci.Spec{
		Linux: &specs.Linux{
			Namespaces: createDefaultLinuxNamespaces(),
			Resources:  &specs.LinuxResources{},
		},
		Process: &specs.Process{},
	}

	dummyContainer := containers.Container{ID: "dummy"}
	for _, opt := range specOpts[1:] { // Skip WithImageConfigArgs
		optName := getFuncName(opt)
		if strings.Contains(optName, "WithDevices") {
			continue // Skip executing the device stat option
		}
		if err := opt(ctx, nil, &dummyContainer, &gotSpec); err != nil {
			t.Fatalf("failed to apply spec option: %v", err)
		}
	}

	want := map[string]string{
		"/usr/local/nvidia/lib64": "/opt/nvidia/620.06/lib64",
		"/usr/local/nvidia/bin":   "/opt/nvidia/620.06/bin",
	}
	for _, mnt := range gotSpec.Mounts {
		if src, ok := want[mnt.Destination]; ok && mnt.Source == src {
			delete(want, mnt.Destination)
		}
	}
	if len(want) != 0 {
		t.Errorf("GB300 CC mode GPU mounts missing (destination -> source): %v; got mounts: %v", want, gotSpec.Mounts)
	}
}

func TestCreateOCISpecOpts_GPU_GB300CCModeNoDriver(t *testing.T) {
	logger := &fakeLogger{}
	img := createFakeImage(nil, nil, nil)

	origFind := findGB300DriverDir
	t.Cleanup(func() { findGB300DriverDir = origFind })
	findGB300DriverDir = func() (string, error) { return "", fmt.Errorf("no driver directory") }

	ls := spec.LaunchSpec{
		InstallGpuDriver: true,
		Experiments: experiments.Experiments{
			GB300CCMode: true,
		},
	}

	if _, err := createOCISpecOpts(img, ls, nil, func(_, _ string) ([]string, error) { return nil, nil }, logger); err == nil {
		t.Error("createOCISpecOpts() without a pre-installed driver in GB300 CC mode succeeded, want error")
	}
}

// stubFindGB300FTPMDevs replaces fTPM discovery for the duration of the test so that
// createOCISpecOpts does not scan the host's /dev. It returns a pointer to a call counter.
func stubFindGB300FTPMDevs(t *testing.T, devs []ftpmDevice, err error) *int {
	t.Helper()
	calls := 0
	orig := findGB300FTPMDevs
	t.Cleanup(func() { findGB300FTPMDevs = orig })
	findGB300FTPMDevs = func() ([]ftpmDevice, error) {
		calls++
		return devs, err
	}
	return &calls
}

func TestCreateOCISpecOpts_GB300CCMode_FTPMDevices(t *testing.T) {
	ctx := namespaces.WithNamespace(context.Background(), "default")
	logger := &fakeLogger{}
	img := createFakeImage(nil, nil, nil)

	// Use distinct real character devices as stand-ins for the resolved fTPM nodes
	// (/dev/tpm1, /dev/tpmrm1), since containerd's oci.WithDevices stats hostPath.
	// discoverFTPMDevs itself is covered by the tests in ftpm_test.go.
	stubFindGB300FTPMDevs(t, []ftpmDevice{
		{hostPath: "/dev/null", containerPath: "/dev/ftpm"},
		{hostPath: "/dev/zero", containerPath: "/dev/ftpmrm"},
	}, nil)
	stubFindGB300FabricSpecOpts(t, nil, nil)

	t.Run("mounted_in_gb300_cc_mode", func(t *testing.T) {
		ls := spec.LaunchSpec{
			Experiments: experiments.Experiments{
				GB300CCMode: true,
			},
		}
		specOpts, err := createOCISpecOpts(img, ls, nil, dummyListFiles, logger)
		if err != nil {
			t.Fatalf("createOCISpecOpts failed: %v", err)
		}
		gotSpec, err := applySpecOptsToSpec(ctx, specOpts)
		if err != nil {
			t.Fatalf("applySpecOptsToSpec failed: %v", err)
		}

		// Map each container path to the expected host device so that a swapped or
		// duplicated hostPath -> containerPath mapping is caught.
		for containerPath, hostPath := range map[string]string{
			"/dev/ftpm":   "/dev/null",
			"/dev/ftpmrm": "/dev/zero",
		} {
			dev := assertCharDeviceInSpec(t, gotSpec, hostPath, containerPath, "rw")
			if dev.FileMode == nil || *dev.FileMode != ftpmContainerFileMode {
				t.Errorf("device %s FileMode = %v, want %#o", containerPath, dev.FileMode, ftpmContainerFileMode)
			}
		}
	})

	t.Run("not_mounted_when_gb300_disabled", func(t *testing.T) {
		ls := spec.LaunchSpec{}
		specOpts, err := createOCISpecOpts(img, ls, nil, dummyListFiles, logger)
		if err != nil {
			t.Fatalf("createOCISpecOpts failed: %v", err)
		}
		gotSpec, err := applySpecOptsToSpec(ctx, specOpts)
		if err != nil {
			t.Fatalf("applySpecOptsToSpec failed: %v", err)
		}
		for _, dev := range gotSpec.Linux.Devices {
			if dev.Path == "/dev/ftpm" || dev.Path == "/dev/ftpmrm" {
				t.Errorf("unexpected fTPM device %s mounted when GB300CCMode=false", dev.Path)
			}
		}
	})
}

// stubFindGB300DriverDir replaces GB300 GPU driver directory lookup for one test.
func stubFindGB300DriverDir(t *testing.T, dir string) {
	t.Helper()
	orig := findGB300DriverDir
	t.Cleanup(func() { findGB300DriverDir = orig })
	findGB300DriverDir = func() (string, error) { return dir, nil }
}

func assertCharDeviceInSpec(t *testing.T, gotSpec specs.Spec, hostPath, containerPath, wantAccess string) specs.LinuxDevice {
	t.Helper()
	wantDev, err := oci.DeviceFromPath(hostPath)
	if err != nil {
		t.Fatalf("oci.DeviceFromPath(%q) failed: %v", hostPath, err)
	}
	var found []specs.LinuxDevice
	for _, dev := range gotSpec.Linux.Devices {
		if dev.Path == containerPath {
			found = append(found, dev)
		}
	}
	if len(found) != 1 {
		t.Fatalf("got %d devices at %s, want 1: %+v", len(found), containerPath, gotSpec.Linux.Devices)
	}
	dev := found[0]
	if dev.Type != "c" || dev.Major != wantDev.Major || dev.Minor != wantDev.Minor {
		t.Errorf("device %s = type %q %d:%d, want type \"c\" %d:%d (%s)", containerPath, dev.Type, dev.Major, dev.Minor, wantDev.Major, wantDev.Minor, hostPath)
	}
	foundRule := false
	for _, cg := range gotSpec.Linux.Resources.Devices {
		if cg.Major != nil && cg.Minor != nil && *cg.Major == wantDev.Major && *cg.Minor == wantDev.Minor {
			foundRule = true
			if !cg.Allow || cg.Type != "c" || cg.Access != wantAccess {
				t.Errorf("device cgroup rule for %s = %+v, want Allow=true Type=c Access=%s", containerPath, cg, wantAccess)
			}
		}
	}
	if !foundRule {
		t.Errorf("no device cgroup rule for %s (%d:%d): %+v", containerPath, wantDev.Major, wantDev.Minor, gotSpec.Linux.Resources.Devices)
	}
	return dev
}

func assertDeviceAbsentInSpec(t *testing.T, gotSpec specs.Spec, hostPath, containerPath string) {
	t.Helper()
	wantDev, err := oci.DeviceFromPath(hostPath)
	if err != nil {
		t.Fatalf("oci.DeviceFromPath(%q) failed: %v", hostPath, err)
	}
	for _, dev := range gotSpec.Linux.Devices {
		if dev.Path == containerPath {
			t.Errorf("unexpected device %s added: %+v", containerPath, dev)
		}
	}
	if gotSpec.Linux.Resources != nil {
		for _, cg := range gotSpec.Linux.Resources.Devices {
			if cg.Major != nil && cg.Minor != nil && *cg.Major == wantDev.Major && *cg.Minor == wantDev.Minor {
				t.Errorf("unexpected device cgroup rule for %s (%d:%d): %+v", containerPath, wantDev.Major, wantDev.Minor, cg)
			}
		}
	}
}

type fabricSpecOptCall struct {
	nonroot bool
	logger  logging.Logger
}

// stubFindGB300FabricSpecOpts replaces IMEX/MNCCD spec option discovery for one
// test and returns the recorded arguments for each invocation.
func stubFindGB300FabricSpecOpts(t *testing.T, opts []oci.SpecOpts, err error) *[]fabricSpecOptCall {
	t.Helper()
	var calls []fabricSpecOptCall
	orig := findGB300FabricSpecOpts
	t.Cleanup(func() { findGB300FabricSpecOpts = orig })
	findGB300FabricSpecOpts = func(nonroot bool, logger logging.Logger) ([]oci.SpecOpts, error) {
		calls = append(calls, fabricSpecOptCall{nonroot: nonroot, logger: logger})
		return opts, err
	}
	return &calls
}

func TestCreateOCISpecOpts_GB300CCMode_FabricSpecOpts(t *testing.T) {
	ctx := namespaces.WithNamespace(context.Background(), "default")
	img := createFakeImage(nil, nil, nil)
	stubFindGB300DriverDir(t, "/opt/nvidia/620.06")
	stubFindGB300FTPMDevs(t, nil, nil)

	imexMount := specs.Mount{
		Type:        "bind",
		Source:      "/usr/bin/nvidia-imex",
		Destination: "/usr/local/nvidia/fabric/bin/nvidia-imex",
		Options:     []string{"bind", "ro"},
	}
	stubOpts := []oci.SpecOpts{
		oci.WithMounts([]specs.Mount{imexMount}),
		oci.WithDevices("/dev/null", "/dev/nvidia-caps-imex-channels/channel3", "rw"),
	}

	tests := []struct {
		name       string
		gb300      bool
		gpuDriver  bool
		nonroot    bool
		wantCalled bool
	}{
		{name: "applied_for_root_in_gb300_cc_mode", gb300: true, gpuDriver: true, wantCalled: true},
		{name: "applied_for_nonroot_in_gb300_cc_mode", gb300: true, gpuDriver: true, nonroot: true, wantCalled: true},
		{name: "skipped_when_gpu_driver_disabled", gb300: true, gpuDriver: false},
		{name: "skipped_when_gb300_disabled", gb300: false, gpuDriver: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			calls := stubFindGB300FabricSpecOpts(t, stubOpts, nil)
			logger := &fakeLogger{}
			ls := spec.LaunchSpec{
				InstallGpuDriver: tc.gpuDriver,
				NonrootContainer: tc.nonroot,
				Experiments:      experiments.Experiments{GB300CCMode: tc.gb300},
			}
			specOpts, err := createOCISpecOpts(img, ls, nil, dummyListFiles, logger)
			if err != nil {
				t.Fatalf("createOCISpecOpts() failed: %v", err)
			}
			gotSpec, err := applySpecOptsToSpec(ctx, specOpts)
			if err != nil {
				t.Fatalf("applySpecOptsToSpec() failed: %v", err)
			}
			if !tc.wantCalled {
				if len(*calls) != 0 {
					t.Fatalf("findGB300FabricSpecOpts called %d time(s), want 0", len(*calls))
				}
				assertDeviceAbsentInSpec(t, gotSpec, "/dev/null", "/dev/nvidia-caps-imex-channels/channel3")
				return
			}
			if len(*calls) != 1 || (*calls)[0].nonroot != tc.nonroot || (*calls)[0].logger != logger {
				t.Fatalf("findGB300FabricSpecOpts calls = %+v, want 1 call with nonroot=%v and logger", *calls, tc.nonroot)
			}
			var gotMounts []specs.Mount
			for _, m := range gotSpec.Mounts {
				if strings.HasPrefix(m.Destination, gb300FabricContainerBinDir+"/") {
					gotMounts = append(gotMounts, m)
				}
			}
			if diff := cmp.Diff([]specs.Mount{imexMount}, gotMounts); diff != "" {
				t.Errorf("IMEX/MNCCD mounts mismatch (-want +got):\n%s", diff)
			}
			assertCharDeviceInSpec(t, gotSpec, "/dev/null", "/dev/nvidia-caps-imex-channels/channel3", "rw")
		})
	}
}

func TestCreateOCISpecOpts_GB300CCMode_FabricErrorFailsClosed(t *testing.T) {
	logger := &fakeLogger{}
	img := createFakeImage(nil, nil, nil)
	stubFindGB300DriverDir(t, "/opt/nvidia/620.06")
	stubFindGB300FTPMDevs(t, nil, nil)

	errFabric := errors.New("unexpected fabric discovery failure")
	stubFindGB300FabricSpecOpts(t, nil, errFabric)

	ls := spec.LaunchSpec{
		InstallGpuDriver: true,
		Experiments:      experiments.Experiments{GB300CCMode: true},
	}
	_, err := createOCISpecOpts(img, ls, nil, dummyListFiles, logger)
	if !errors.Is(err, errFabric) || !strings.Contains(err.Error(), "failed to discover GB300 IMEX/MNCCD mounts and devices") {
		t.Fatalf("createOCISpecOpts() error = %v, want error wrapping %v with 'failed to discover GB300 IMEX/MNCCD mounts and devices'", err, errFabric)
	}
}

func TestCreateOCISpecOpts_GB300CCMode_DefaultFabricWiring(t *testing.T) {
	ctx := namespaces.WithNamespace(context.Background(), "default")
	img := createFakeImage(nil, nil, nil)
	stubFindGB300DriverDir(t, "/opt/nvidia/620.06")
	stubFindGB300FTPMDevs(t, nil, nil)

	allBins := []string{"nvidia-imex", "nvidia-imex-ctl", "nvidia-mnccd"}
	ls := spec.LaunchSpec{
		InstallGpuDriver: true,
		Experiments:      experiments.Experiments{GB300CCMode: true},
	}

	t.Run("happy_path_mounts_binaries_and_devices_with_rw_access", func(t *testing.T) {
		cfg := setupFabricSpecFixture(t, allBins, "",
			channelFixture{symlinks: map[string]string{"channel3": "/dev/null"}},
			map[string]capFixture{
				"fabric-imex-mgmt": {procContent: "DeviceFileMinor: 5\n", nodeName: "nvidia-cap5", nodeTarget: "/dev/zero"},
				"mncc-mgmt":        {procContent: "DeviceFileMinor: 8\n", nodeName: "nvidia-cap8", nodeTarget: "/dev/random"},
			},
			"Character devices:\n  1 nvidia-caps-imex-channels\n  1 nvidia-caps\n",
		)
		origCfg := defaultGB300FabricConfig
		t.Cleanup(func() { defaultGB300FabricConfig = origCfg })
		defaultGB300FabricConfig.binaries = cfg.binaries
		defaultGB300FabricConfig.devRoot = cfg.devRoot
		defaultGB300FabricConfig.procRoot = cfg.procRoot

		logger := &fakeLogger{}
		specOpts, err := createOCISpecOpts(img, ls, nil, dummyListFiles, logger)
		if err != nil {
			t.Fatalf("createOCISpecOpts() failed: %v", err)
		}
		gotSpec, err := applySpecOptsToSpec(ctx, specOpts)
		if err != nil {
			t.Fatalf("applySpecOptsToSpec() failed: %v", err)
		}
		for _, e := range logger.errors {
			if strings.Contains(e, "IMEX/MNCCD") {
				t.Errorf("unexpected IMEX/MNCCD error log: %s", e)
			}
		}
		assertFabricBinMountsInSpec(t, gotSpec, filepath.Dir(cfg.binaries[0]), allBins)
		assertCharDeviceInSpec(t, gotSpec, "/dev/null", filepath.Join(cfg.devRoot, "nvidia-caps-imex-channels", "channel3"), "rw")
		assertCharDeviceInSpec(t, gotSpec, "/dev/zero", filepath.Join(cfg.devRoot, "nvidia-caps", "nvidia-cap5"), "rw")
		assertCharDeviceInSpec(t, gotSpec, "/dev/random", filepath.Join(cfg.devRoot, "nvidia-caps", "nvidia-cap8"), "rw")
	})

	t.Run("regular_file_channel_rejected_by_default_charDevStat", func(t *testing.T) {
		cfg := setupFabricSpecFixture(t, allBins, "",
			channelFixture{files: []string{"channel3"}},
			nil,
			"Character devices:\n  1 nvidia-caps-imex-channels\n  1 nvidia-caps\n",
		)
		origCfg := defaultGB300FabricConfig
		t.Cleanup(func() { defaultGB300FabricConfig = origCfg })
		defaultGB300FabricConfig.binaries = cfg.binaries
		defaultGB300FabricConfig.devRoot = cfg.devRoot
		defaultGB300FabricConfig.procRoot = cfg.procRoot

		logger := &fakeLogger{}
		_, err := createOCISpecOpts(img, ls, nil, dummyListFiles, logger)
		if err == nil || !strings.Contains(err.Error(), "not a character device") {
			t.Fatalf("createOCISpecOpts() error = %v, want error containing 'not a character device'", err)
		}
	})
}

func TestCreateOCISpecOpts_GB300CCMode_NonrootContainerSkipsFTPM(t *testing.T) {
	ctx := namespaces.WithNamespace(context.Background(), "default")
	logger := &fakeLogger{}
	img := createFakeImage(nil, nil, nil)

	// Discovery would fail if it ran, so success also shows that it is not attempted.
	calls := stubFindGB300FTPMDevs(t, nil, errors.New("fTPM discovery must not run for non-root containers"))
	stubFindGB300FabricSpecOpts(t, nil, nil)

	ls := spec.LaunchSpec{
		NonrootContainer: true,
		Experiments: experiments.Experiments{
			GB300CCMode: true,
		},
	}
	specOpts, err := createOCISpecOpts(img, ls, nil, dummyListFiles, logger)
	if err != nil {
		t.Fatalf("createOCISpecOpts() failed for non-root container: %v", err)
	}
	if *calls != 0 {
		t.Errorf("fTPM discovery ran %d time(s) for a non-root container, want 0", *calls)
	}
	gotSpec, err := applySpecOptsToSpec(ctx, specOpts)
	if err != nil {
		t.Fatalf("applySpecOptsToSpec failed: %v", err)
	}
	for _, dev := range gotSpec.Linux.Devices {
		if dev.Path == "/dev/ftpm" || dev.Path == "/dev/ftpmrm" {
			t.Errorf("unexpected fTPM device %s mounted for non-root container", dev.Path)
		}
	}
}

func TestCreateOCISpecOpts_GB300CCMode_NoFTPMDevicesSkipped(t *testing.T) {
	logger := &fakeLogger{}
	img := createFakeImage(nil, nil, nil)

	stubFindGB300FTPMDevs(t, nil, nil)
	stubFindGB300FabricSpecOpts(t, nil, nil)

	ls := spec.LaunchSpec{
		Experiments: experiments.Experiments{
			GB300CCMode: true,
		},
	}
	if _, err := createOCISpecOpts(img, ls, nil, dummyListFiles, logger); err != nil {
		t.Fatalf("createOCISpecOpts() failed when fTPM symlinks are absent on host: %v", err)
	}
}

func TestCreateOCISpecOpts_GB300CCMode_InvalidFTPMFailsClosed(t *testing.T) {
	logger := &fakeLogger{}
	img := createFakeImage(nil, nil, nil)

	errDiscovery := errors.New("incomplete GB300 fTPM device symlinks")
	stubFindGB300FTPMDevs(t, nil, errDiscovery)

	ls := spec.LaunchSpec{
		Experiments: experiments.Experiments{
			GB300CCMode: true,
		},
	}
	_, err := createOCISpecOpts(img, ls, nil, dummyListFiles, logger)
	if !errors.Is(err, errDiscovery) || !strings.Contains(err.Error(), "failed to discover GB300 fTPM devices") {
		t.Fatalf("createOCISpecOpts() error = %v, want error wrapping %v with 'failed to discover GB300 fTPM devices'", err, errDiscovery)
	}
}

func TestCreateOCISpecOpts_GPU_Error(t *testing.T) {
	logger := &fakeLogger{}
	img := createFakeImage(nil, nil, nil)

	// Inject a scanner that fails
	mockListFilesError := func(_, _ string) ([]string, error) {
		return nil, fmt.Errorf("device filesystem scan failed")
	}

	ls := spec.LaunchSpec{
		InstallGpuDriver: true,
	}

	_, err := createOCISpecOpts(img, ls, nil, mockListFilesError, logger)
	if err == nil {
		t.Fatalf("expected createOCISpecOpts to fail when listFiles fails, but got no error")
	}
	if !strings.Contains(err.Error(), "device filesystem scan failed") {
		t.Errorf("expected error to wrap 'device filesystem scan failed', got: %v", err)
	}
}

func TestCreateOCISpecOpts_DevShmSize(t *testing.T) {
	ctx := namespaces.WithNamespace(context.Background(), "default")
	logger := &fakeLogger{}
	img := createFakeImage(nil, nil, nil)

	ls := spec.LaunchSpec{
		DevShmSize: 1048576, // 1MB
	}

	specOpts, err := createOCISpecOpts(img, ls, nil, dummyListFiles, logger)
	if err != nil {
		t.Fatalf("createOCISpecOpts failed: %v", err)
	}

	gotSpec, err := applySpecOptsToSpec(ctx, specOpts)
	if err != nil {
		t.Fatalf("failed to apply spec option: %v", err)
	}

	// Verify that /dev/shm mount exists with the custom size option
	foundShmMount := false
	for _, mnt := range gotSpec.Mounts {
		if mnt.Destination == "/dev/shm" && mnt.Type == "tmpfs" {
			for _, opt := range mnt.Options {
				if strings.HasPrefix(opt, "size=1048576") {
					foundShmMount = true
				}
			}
		}
	}
	if !foundShmMount {
		t.Errorf("Expected custom size /dev/shm mount not found in spec: %v", gotSpec.Mounts)
	}
}

func TestFormatEnvVars_Error(t *testing.T) {
	invalidEnvs := []spec.EnvVar{
		{Name: "1INVALID", Value: "value"}, // starts with a digit
	}

	_, err := formatEnvVars(invalidEnvs)
	if err == nil {
		t.Fatalf("expected formatEnvVars to fail on invalid env name, but got no error")
	}
	if !strings.Contains(err.Error(), "malformed env name") {
		t.Errorf("expected error to contain 'malformed env name', got: %v", err)
	}
}
