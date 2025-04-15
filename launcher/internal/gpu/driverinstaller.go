// Package gpu provides the devices information for cos-gpu-installer
package gpu

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"cos.googlesource.com/cos/tools.git/src/cmd/cos_gpu_installer/deviceinfo"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/oci"
	"github.com/google/go-tpm-tools/launcher/internal/logging"
	"github.com/google/go-tpm-tools/launcher/spec"
	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/opencontainers/runtime-spec/specs-go"
)

const (
	installerContainerID = "tee-gpu-driver-installer-container"
	installerSnapshotID  = "tee-gpu-driver-installer-snapshot"
)

var supportedCGPUTypes = []deviceinfo.GPUType{
	deviceinfo.H100,
}

type nvidiaSmiCmdOutput func() ([]byte, error)
type nvidiaSmiCmdRun func() error

// DriverInstaller contains information about the GPU driver installer settings
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
// README specifies docker command where this function uses containerd for launching and managing the GPU driver installer container.
func (di *DriverInstaller) InstallGPUDrivers(ctx context.Context) error {
	err := remountAsExecutable(InstallationHostDir)
	if err != nil {
		return fmt.Errorf("failed to remount the installation directory: %v", err)
	}

	gpuType, err := deviceinfo.GetGPUTypeInfo()
	if err != nil {
		return fmt.Errorf("failed to get the GPU type info: %v", err)
	}

	err = isConfidentialComputeSupported(gpuType, supportedCGPUTypes)
	if err != nil {
		return err
	}

	ctx = namespaces.WithNamespace(ctx, namespaces.Default)
	installerImageRef, err := getInstallerImageReference(InstallerImageRefFile)
	if err != nil {
		di.logger.Error(fmt.Sprintf("failed to get the installer container image reference: %v", err))
		return err
	}

	di.logger.Info(fmt.Sprintf("COS GPU installer version : %s", installerImageRef))
	image, err := di.cdClient.Pull(ctx, installerImageRef, containerd.WithPullUnpack)
	if err != nil {
		return fmt.Errorf("failed to pull installer image: %v", err)
	}

	if err := verifyInstallerImageDigest(image, InstallerImageDigestFile); err != nil {
		return err
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
		di.logger.Error(fmt.Sprintf("cannot get hostname: %v", err))
	}

	container, err := di.cdClient.NewContainer(
		ctx,
		installerContainerID,
		containerd.WithImage(image),
		containerd.WithNewSnapshot(installerSnapshotID, image),
		containerd.WithNewSpec(oci.WithImageConfig(image),
			oci.WithPrivileged,
			// To support confidential GPUs, the nvidia-persistenced process should be started before the GPU driver verification step.
			// It would not be possible to start the nvidia-persistenced process amidst GPU driver installation flow via cos_gpu_installer.
			// For this reason, the GPU driver installation need to be triggered with --skip-nvidia-smi flag to skip the GPU driver verification step.
			oci.WithProcessArgs("/cos-gpu-installer", "install", "-version=default", fmt.Sprintf("-host-dir=%s", InstallationHostDir), "--skip-nvidia-smi"),
			oci.WithAllDevicesAllowed,
			oci.WithHostDevices,
			oci.WithMounts(mounts),
			oci.WithHostNamespace(specs.NetworkNamespace),
			oci.WithHostNamespace(specs.PIDNamespace),
			oci.WithHostHostsFile,
			oci.WithHostResolvconf,
			oci.WithEnv([]string{fmt.Sprintf("HOSTNAME=%s", hostname)})))
	if err != nil {
		return fmt.Errorf("failed to create GPU driver installer container: %v", err)
	}
	defer container.Delete(ctx, containerd.WithSnapshotCleanup)

	task, err := container.NewTask(ctx, cio.NewCreator(cio.WithStdio))
	if err != nil {
		return fmt.Errorf("failed to create GPU driver installation task: %v", err)
	}
	defer task.Delete(ctx)

	statusC, err := task.Wait(ctx)
	if err != nil {
		return fmt.Errorf("failed to wait for GPU driver installation task: %v", err)
	}

	if err := task.Start(ctx); err != nil {
		return fmt.Errorf("failed to start GPU driver installation task: %v", err)
	}

	status := <-statusC
	code, _, _ := status.Result()

	if code != 0 {
		di.logger.Error(fmt.Sprintf("GPU driver installation task ended and returned non-zero status code %d", code))
		return fmt.Errorf("GPU driver installation task ended with non-zero status code %d", code)
	}

	if err = launchNvidiaPersistencedProcess(di.logger); err != nil {
		return fmt.Errorf("failed to start nvidia-persistenced process: %v", err)
	}

	nvidiaSmiVerifyCmd := nvidiaSmiRunFunc()
	if err = verifyDriverInstallation(nvidiaSmiVerifyCmd); err != nil {
		return fmt.Errorf("failed to verify GPU driver installation: %v", err)
	}

	nvidiaSmiCCModeCmd := nvidiaSmiOutputFunc("conf-compute", "-f")
	nvidiaSmiDevToolsCmd := nvidiaSmiOutputFunc("conf-compute", "-d")

	ccEnabled, err := QueryCCMode(nvidiaSmiCCModeCmd, nvidiaSmiDevToolsCmd)
	if err != nil {
		return fmt.Errorf("failed to check confidential compute mode status: %v", err)
	}
	// Explicitly need to set the GPU state to READY for GPUs with confidential compute mode ON.
	if ccEnabled == attest.GPUDeviceCCMode_ON {
		setGPUStateCmd := nvidiaSmiRunFunc("conf-compute", "-srs", "1")
		if err = setGPUStateToReady(setGPUStateCmd); err != nil {
			return fmt.Errorf("failed to set the GPU state to ready: %v", err)
		}
	}

	di.logger.Info("GPU driver installation completed successfully")
	return nil
}

func getInstallerImageReference(installerImageRefFile string) (string, error) {
	imageRefBytes, err := os.ReadFile(installerImageRefFile)
	if err != nil {
		return "", fmt.Errorf("failed to get the cos-gpu-installer version: %v", err)
	}
	installerImageRef := strings.TrimSpace(string(imageRefBytes))
	if len(installerImageRef) == 0 {
		return "", fmt.Errorf("empty value of cos-gpu-installer image reference")
	}
	return installerImageRef, nil
}

func verifyInstallerImageDigest(image containerd.Image, referenceDigestFile string) error {
	installerDigest := image.Target().Digest.String()
	imageDigestBytes, err := os.ReadFile(referenceDigestFile)
	if err != nil {
		return fmt.Errorf("failed to get the cos-gpu-installer image digest: %v", err)
	}
	expectedInstallerDigest := strings.TrimSpace(string(imageDigestBytes))
	if installerDigest != expectedInstallerDigest {
		return fmt.Errorf("cos_gpu_installer image digest verification failed - expected : %s, actual : %s", expectedInstallerDigest, installerDigest)
	}
	return nil
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

func verifyDriverInstallation(nvidiaSmiVerifyCmd nvidiaSmiCmdRun) error {
	if err := nvidiaSmiVerifyCmd(); err != nil {
		return fmt.Errorf("failed to verify GPU driver installation : %v", err)
	}
	return nil
}

func setGPUStateToReady(nvidiaSmiSetGPUStateCmd nvidiaSmiCmdRun) error {
	if err := nvidiaSmiSetGPUStateCmd(); err != nil {
		return fmt.Errorf("failed to set the GPU state to ready: %v", err)
	}
	return nil
}

// QueryCCMode executes nvidia-smi to determine the current Confidential Computing (CC) mode status of the GPU.
// If DEVTOOLS mode is enabled, it would override CC mode as DEVTOOLS. DEVTOOLS mode would be enabled only when CC mode is ON.
func QueryCCMode(nvidiaSmiCCModeCmd, nvidiaSmiDevToolsCmd nvidiaSmiCmdOutput) (attest.GPUDeviceCCMode, error) {
	ccMode := attest.GPUDeviceCCMode_UNSET
	ccModeOutput, err := nvidiaSmiCCModeCmd()
	if err != nil {
		return attest.GPUDeviceCCMode_UNSET, err
	}

	devToolsOutput, err := nvidiaSmiDevToolsCmd()
	if err != nil {
		return attest.GPUDeviceCCMode_UNSET, err
	}

	if strings.Contains(string(ccModeOutput), "CC Status: ON") {
		ccMode = attest.GPUDeviceCCMode_ON
	} else if strings.Contains(string(ccModeOutput), "CC Status: OFF") {
		ccMode = attest.GPUDeviceCCMode_OFF
	}

	if ccMode == attest.GPUDeviceCCMode_ON && strings.Contains(string(devToolsOutput), "DevTools Mode: ON") {
		ccMode = attest.GPUDeviceCCMode_DEVTOOLS
	}

	return ccMode, nil
}

func launchNvidiaPersistencedProcess(logger logging.Logger) error {
	nvidiaPersistencedCmd := fmt.Sprintf("%s/bin/nvidia-persistenced", InstallationHostDir)
	logger.Info("Starting nvidia-persistenced process")
	if err := exec.Command(nvidiaPersistencedCmd).Run(); err != nil {
		return fmt.Errorf("failed to launch nvidia-persistenced daemon: %v", err)
	}
	logger.Info("nvidia-persistenced daemon successfully started")
	return nil
}

func isConfidentialComputeSupported(gpuType deviceinfo.GPUType, supportedCGPUTypes []deviceinfo.GPUType) error {
	if !gpuType.OpenSupported() {
		return fmt.Errorf("open sourced kernel modules are not supported for GPU type %s", gpuType)
	}
	for _, supportedType := range supportedCGPUTypes {
		if gpuType == supportedType {
			return nil
		}
	}
	return fmt.Errorf("unsupported confidential GPU type %s, please retry with one of the supported confidential GPU types: %v", gpuType.String(), supportedCGPUTypes)
}

func nvidiaSmiOutputFunc(args ...string) nvidiaSmiCmdOutput {
	nvidiaSmiCmd := fmt.Sprintf("%s/bin/nvidia-smi", InstallationHostDir)
	return func() ([]byte, error) { return exec.Command(nvidiaSmiCmd, args...).Output() }
}

func nvidiaSmiRunFunc(args ...string) nvidiaSmiCmdRun {
	nvidiaSmiCmd := fmt.Sprintf("%s/bin/nvidia-smi", InstallationHostDir)
	return func() error { return exec.Command(nvidiaSmiCmd, args...).Run() }
}
