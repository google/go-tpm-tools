// Package gpu provides the devices information for cos-gpu-installer
package gpu

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"cos.googlesource.com/cos/tools.git/src/cmd/cos_gpu_installer/deviceinfo"
	"cos.googlesource.com/cos/tools.git/src/pkg/cos"
	"cos.googlesource.com/cos/tools.git/src/pkg/modules"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/oci"
	"github.com/google/go-tpm-tools/launcher/internal/logging"
	"github.com/google/go-tpm-tools/launcher/internal/systemctl"
	"github.com/google/go-tpm-tools/launcher/spec"
	"github.com/opencontainers/runtime-spec/specs-go"
)

const (
	installerContainerID = "tee-gpu-driver-installer-container"
	installerSnapshotID  = "tee-gpu-driver-installer-snapshot"
)

var supportedGpuTypes = []deviceinfo.GPUType{
	deviceinfo.L4,
	deviceinfo.T4,
	deviceinfo.A100_40GB,
	deviceinfo.A100_80GB,
	deviceinfo.H100,
}

// DriverInstaller contains information about the gpu driver installer settings
type DriverInstaller struct {
	cdClient   *containerd.Client
	launchSpec spec.LaunchSpec
	logger     logging.Logger
}

// NewDriverInstaller instanciates an object of driver installer
func NewDriverInstaller(cdClient *containerd.Client, launchSpec spec.LaunchSpec, logger logging.Logger) *DriverInstaller {
	return &DriverInstaller{
		cdClient:   cdClient,
		launchSpec: launchSpec,
		logger:     logger,
	}
}

// InstallGPUDrivers installs the GPU driver on host machine using the cos-gpu-installer container.
// This function performs the same steps specified in this README file:
// https://pkg.go.dev/cos.googlesource.com/cos/tools.git@v0.0.0-20241008015903-8431fe581b1f/src/cmd/cos_gpu_installer#section-readme
// README specifies docker command where this function uses containerd for launching and managing the gpu driver installer container.
func (di *DriverInstaller) InstallGPUDrivers(ctx context.Context) error {
	err := remountAsExecutable(InstallationHostDir)
	if err != nil {
		return fmt.Errorf("failed to remount the installation directory: %v", err)
	}

	gpuType, err := deviceinfo.GetGPUTypeInfo()
	if err != nil {
		return fmt.Errorf("failed to get the gpu type info: %v", err)
	}

	if !gpuType.OpenSupported() {
		return fmt.Errorf("unsupported gpu type %s, please retry with one of the supported gpu types: %v", gpuType.String(), supportedGpuTypes)
	}

	ctx = namespaces.WithNamespace(ctx, namespaces.Default)
	installerImageRef, err := getInstallerImageReference()
	if err != nil {
		di.logger.Error("failed to get the installer container image reference: %v", err)
		return err
	}

	di.logger.Printf("cos gpu installer version : %s", installerImageRef)
	image, err := di.cdClient.Pull(ctx, installerImageRef, containerd.WithPullUnpack)
	if err != nil {
		return fmt.Errorf("failed to pull installer image: %v", err)
	}

	mounts := []specs.Mount{
		{
			Type:        "volume",
			Source:      "/dev",
			Destination: "/dev",
			Options:     []string{"rbind", "rw"},
		}, {
			Type:        "volume",
			Source:      "/",
			Destination: "/root",
			Options:     []string{"rbind", "rw"},
		},
	}

	hostname, err := os.Hostname()
	if err != nil {
		di.logger.Error("cannot get hostname: %v", err)
	}

	container, err := di.cdClient.NewContainer(
		ctx,
		installerContainerID,
		containerd.WithImage(image),
		containerd.WithNewSnapshot(installerSnapshotID, image),
		containerd.WithNewSpec(oci.WithImageConfig(image),
			oci.WithPrivileged,
			oci.WithProcessArgs("/cos-gpu-installer", "install", "-version=default", fmt.Sprintf("-host-dir=%s", InstallationHostDir), "--no-verify"),
			oci.WithAllDevicesAllowed,
			oci.WithHostDevices,
			oci.WithMounts(mounts),
			oci.WithHostNamespace(specs.NetworkNamespace),
			oci.WithHostNamespace(specs.PIDNamespace),
			oci.WithHostHostsFile,
			oci.WithHostResolvconf,
			oci.WithEnv([]string{fmt.Sprintf("HOSTNAME=%s", hostname)})))
	if err != nil {
		return fmt.Errorf("failed to create gpu driver installer container: %v", err)
	}
	defer container.Delete(ctx, containerd.WithSnapshotCleanup)

	task, err := container.NewTask(ctx, cio.NewCreator(cio.WithStdio))
	if err != nil {
		return fmt.Errorf("failed to create gpu driver installation task: %v", err)
	}
	defer task.Delete(ctx)

	statusC, err := task.Wait(ctx)
	if err != nil {
		return fmt.Errorf("failed to wait for gpu driver installation task: %v", err)
	}

	if err := task.Start(ctx); err != nil {
		return fmt.Errorf("failed to start gpu driver installation task: %v", err)
	}

	status := <-statusC
	code, _, _ := status.Result()

	if code != 0 {
		di.logger.Error("GPU driver installation task ended and returned non-zero status code %d", code)
		return fmt.Errorf("gpu driver installation task ended with non-zero status code %d", code)
	}

	moduleParams := modules.NewModuleParameters()
	if err = loadGPUDrivers(moduleParams); err != nil {
		return fmt.Errorf("failed load GPU drivers: %v", err)
	}

	if err = startNvidiaPersistencedService(di.logger); err != nil {
		return fmt.Errorf("failed to start nvidia-persistenced process: %v", err)
	}

	if err = verifyDriverInstallation(); err != nil {
		return fmt.Errorf("failed to verify gpu driver installation: %v", err)
	}

	if err = setGPUStateToReady(); err != nil {
		return fmt.Errorf("failed to set the gpu state to ready: %v", err)
	}

	di.logger.Info("GPU driver installation completed succesfully")
	return nil
}

func getInstallerImageReference() (string, error) {
	installerImageRefBytes, err := exec.Command("cos-extensions", "list", "--", "--gpu-installer").Output()
	if err != nil {
		return "", fmt.Errorf("failed to get the cos-gpu-installer version: %v", err)
	}
	installerImageRef := strings.TrimSpace(string(installerImageRefBytes))
	return installerImageRef, nil
}

func remountAsExecutable(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create dir %q: %v", dir, err)
	}
	if err := exec.Command("mount", "--bind", dir, dir).Run(); err != nil {
		return fmt.Errorf("failed to create bind mount at %q: %v", dir, err)
	}
	if err := exec.Command("mount", "-o", "remount,exec", dir).Run(); err != nil {
		return fmt.Errorf("failed to remount %q: %v", dir, err)
	}
	return nil
}

func verifyDriverInstallation() error {
	// Run nvidia-smi to check whether nvidia GPU driver is installed.
	if err := exec.Command("nvidia-smi").Run(); err != nil {
		return fmt.Errorf("failed to verify gpu driver installation : %v", err)
	}
	return nil
}

func setGPUStateToReady() error {
	// Run nvidia-smi conf-compute command to set GPU state to READY.
	if err := exec.Command("nvidia-smi", "conf-compute", "-srs", "1").Run(); err != nil {
		return fmt.Errorf("failed to set the gpu state to ready: %v", err)
	}
	return nil
}

func startNvidiaPersistencedService(logger logging.Logger) error {
	s, err := systemctl.New()
	if err != nil {
		return fmt.Errorf("failed to create systemctl client: %v", err)
	}
	defer s.Close()

	logger.Info("Starting nvidia-persistenced.service")
	if err := s.Start("nvidia-persistenced.service"); err != nil {
		return fmt.Errorf("failed to start nvidia-persistenced.service")
	}

	logger.Info("nvidia-persistenced.service successfully started")
	return nil
}

func loadGPUDrivers(moduleParams modules.ModuleParameters) error {
	envReader, err := cos.NewEnvReader(HostRootPath)
	if err != nil {
		return fmt.Errorf("failed to create envReader with host root path %s", HostRootPath)
	}
	kernelDriversPath := filepath.Join(HostRootPath, "/lib/modules", envReader.KernelRelease(), "kernel/drivers")
	kernelModulePath := filepath.Join(InstallationHostDir, "drivers")
	drmPanel := &modules.Module{
		Name:         "drm_panel_orientation_quirks",
		Path:         filepath.Join(kernelDriversPath, "gpu/drm/drm_panel_orientation_quirks.ko"),
		SkipNotFound: true,
	}
	i2c := &modules.Module{
		Name:         "i2c_core",
		Path:         filepath.Join(kernelDriversPath, "i2c/i2c-core.ko"),
		Deps:         []*modules.Module{drmPanel},
		SkipNotFound: true,
	}
	drm := &modules.Module{
		Name:         "drm",
		Path:         filepath.Join(kernelDriversPath, "gpu/drm/drm.ko"),
		Deps:         []*modules.Module{i2c, drmPanel},
		SkipNotFound: true,
	}
	drmKms := &modules.Module{
		Name:         "drm_kms_helper",
		Path:         filepath.Join(kernelDriversPath, "gpu/drm/drm_kms_helper.ko"),
		Deps:         []*modules.Module{drm, i2c},
		SkipNotFound: true,
	}
	nvidia := &modules.Module{
		Name: "nvidia",
		Path: filepath.Join(kernelModulePath, "nvidia.ko"),
		Deps: []*modules.Module{drm, i2c},
	}
	nvidiaUvm := &modules.Module{
		Name: "nvidia_uvm",
		Path: filepath.Join(kernelModulePath, "nvidia-uvm.ko"),
		Deps: []*modules.Module{nvidia},
	}
	nvidiaModeset := &modules.Module{
		Name: "nvidia_modeset",
		Path: filepath.Join(kernelModulePath, "nvidia-modeset.ko"),
		Deps: []*modules.Module{nvidia},
	}
	nvidiaDrm := &modules.Module{
		Name: "nvidia_drm",
		Path: filepath.Join(kernelModulePath, "nvidia-drm.ko"),
		Deps: []*modules.Module{nvidiaModeset, drmKms},
	}
	// Need to load modules in order due to module dependency.
	gpuModules := []*modules.Module{nvidia, nvidiaUvm, nvidiaModeset, nvidiaDrm}
	for _, module := range gpuModules {
		if err := modules.LoadModule(module, moduleParams); err != nil {
			return fmt.Errorf("failed to load module %s", module.Path)
		}
	}
	return nil
}
