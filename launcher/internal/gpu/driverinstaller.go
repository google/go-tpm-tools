// Package gpu provides the devices information for cos-gpu-installer
package gpu

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"cos.googlesource.com/cos/tools.git/src/cmd/cos_gpu_installer/deviceinfo"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/oci"
	"github.com/google/go-tpm-tools/launcher/internal/logging"
	"github.com/google/go-tpm-tools/launcher/spec"
	"github.com/opencontainers/runtime-spec/specs-go"
)

// CCMode enums
const (
	CCModeON             CCMode = "ON"
	CCModeOFF            CCMode = "OFF"
	installerContainerID        = "tee-gpu-driver-installer-container"
	installerSnapshotID         = "tee-gpu-driver-installer-snapshot"
)

var supportedCGPUTypes = []deviceinfo.GPUType{
	deviceinfo.H100,
}

// CCMode represents the status confidential computing mode of the GPU.
type CCMode string

func (ccm CCMode) isValid() error {
	switch ccm {
	case CCModeOFF, CCModeON:
		return nil
	}
	return fmt.Errorf("invalid gpu cc mode: %s", ccm)
}

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

	if !gpuType.OpenSupported() {
		return fmt.Errorf("unsupported GPU type %s, please retry with one of the supported confidential GPU types: %v", gpuType.String(), supportedCGPUTypes)
	}

	ctx = namespaces.WithNamespace(ctx, namespaces.Default)
	installerImageRef, err := getInstallerImageReference()
	if err != nil {
		di.logger.Error(fmt.Sprintf("failed to get the installer container image reference: %v", err))
		return err
	}

	di.logger.Info(fmt.Sprintf("COS GPU installer version : %s", installerImageRef))
	image, err := di.cdClient.Pull(ctx, installerImageRef, containerd.WithPullUnpack)
	if err != nil {
		return fmt.Errorf("failed to pull installer image: %v", err)
	}

	installerDigest := image.Target().Digest.String()
	if err := verifyInstallerImageDigest(installerDigest); err != nil {
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

	if err = verifyDriverInstallation(); err != nil {
		return fmt.Errorf("failed to verify GPU driver installation: %v", err)
	}

	ccEnabled, err := isGPUCCModeEnabled()
	if err != nil {
		return fmt.Errorf("failed to check confidential compute mode status: %v", err)
	}
	// Explicitly need to set the GPU state to READY for GPUs with confidential compute mode ON.
	if ccEnabled {
		if err = setGPUStateToReady(); err != nil {
			return fmt.Errorf("failed to set the GPU state to ready: %v", err)
		}
	} else {
		return fmt.Errorf("confidential compute is not enabled for the gpu type %s", gpuType)
	}

	di.logger.Info("GPU driver installation completed successfully")
	return nil
}

func getInstallerImageReference() (string, error) {
	imageRefBytes, err := os.ReadFile(InstallerImageRefFile)
	if err != nil {
		return "", fmt.Errorf("failed to get the cos-gpu-installer version: %v", err)
	}
	installerImageRef := strings.TrimSpace(string(imageRefBytes))
	return installerImageRef, nil
}

func verifyInstallerImageDigest(installerDigest string) error {
	imageDigestBytes, err := os.ReadFile(InstallerImageDigestFile)
	if err != nil {
		return fmt.Errorf("failed to get the cos-gpu-installer image digest: %v", err)
	}
	expectedInstallerDigest := strings.TrimSpace(string(imageDigestBytes))
	if installerDigest == expectedInstallerDigest {
		return nil
	}
	return fmt.Errorf("cos_gpu_installer image digest verification failed - expected : %s, actual : %s", expectedInstallerDigest, installerDigest)
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
	nvidiaSmiCmd := fmt.Sprintf("%s/bin/nvidia-smi", InstallationHostDir)
	if err := exec.Command(nvidiaSmiCmd).Run(); err != nil {
		return fmt.Errorf("failed to verify GPU driver installation : %v", err)
	}
	return nil
}

func setGPUStateToReady() error {
	// Run nvidia-smi conf-compute command to set GPU state to READY.
	nvidiaSmiCmd := fmt.Sprintf("%s/bin/nvidia-smi", InstallationHostDir)
	if err := exec.Command(nvidiaSmiCmd, "conf-compute", "-srs", "1").Run(); err != nil {
		return fmt.Errorf("failed to set the GPU state to ready: %v", err)
	}
	return nil
}

func isGPUCCModeEnabled() (bool, error) {
	ccMode, err := GetGPUCCMode()
	if err != nil {
		return false, err
	}
	return ccMode == CCModeON, nil
}

// GetGPUCCMode executes nvidia-smi to determine the current Confidential Computing (CC) mode status of the GPU.
// It returns the CC mode ("ON" or "OFF") and an error if the command fails or if the output cannot be parsed.
func GetGPUCCMode() (CCMode, error) {
	// Run nvidia-smi conf-compute command to get the confidential computing mode status.
	nvidiaSmiCmd := fmt.Sprintf("%s/bin/nvidia-smi", InstallationHostDir)
	ccModeOutput, err := exec.Command(nvidiaSmiCmd, "conf-compute", "-f").Output()
	if err != nil {
		return "", err
	}
	ccMode, err := parseCCStatus(string(ccModeOutput))
	if err != nil {
		return "", err
	}
	return CCMode(ccMode), nil
}

func parseCCStatus(output string) (CCMode, error) {
	re := regexp.MustCompile(`CC status:\s*(ON|OFF)`)
	match := re.FindStringSubmatch(output)

	if len(match) < 2 {
		return "", fmt.Errorf("CC status not found in output: %s", output)
	}
	ccMode := CCMode(match[1])
	if err := ccMode.isValid(); err != nil {
		return "", err
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
