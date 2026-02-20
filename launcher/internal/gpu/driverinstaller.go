// Package gpu provides the devices information for cos-gpu-installer
package gpu

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path"
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

// NvidiaSmiCmdOutput defines a function type for executing an NVIDIA SMI command
// and returning the raw byte output along with any error.
type NvidiaSmiCmdOutput func() ([]byte, error)

// DriverInstaller contains information about the GPU driver installer settings
type DriverInstaller struct {
	cdClient   *containerd.Client
	launchSpec spec.LaunchSpec
	logger     logging.Logger
}

// NewDriverInstaller instantiates an object of driver installer
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

	switch gpuType {
	case deviceinfo.B200:
	case deviceinfo.H100:
	default:
		return fmt.Errorf("unsupported GPU type %s for Confidential Computing (only supported for H100[a3-highgpu-1g] and B200[a4-highgpu-8g])", gpuType.String())
	}

	ctx = namespaces.WithNamespace(ctx, namespaces.Default)
	di.logger.Info(fmt.Sprintf("COS GPU installer version : %s", InstallerImageRef))
	image, err := di.cdClient.Pull(ctx, InstallerImageRef, containerd.WithPullUnpack)
	if err != nil {
		return fmt.Errorf("failed to pull installer image: %v", err)
	}
	if err := verifyInstallerImageDigest(image, InstallerDigest); err != nil {
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
			oci.WithProcessArgs("/cos-gpu-installer", "install",
				"--gcs-download-bucket=cos-image-hah",                              // TODO: remove once bug fix
				"--gcs-download-prefix=r125-19216-224-0/R125-19216.224.0-a7894d45", // TODO: remove once bug fix
				fmt.Sprintf("-version=%s", NvDriverVer590_48_01),
				fmt.Sprintf("-host-dir=%s", InstallationHostDir),
				"--no-verify"),
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

	if err = verifyDriverDigest(path.Join(InstallationHostDir, NvDriverVer590_48_01Runfile), NvDriverVer590_48_01Digest); err != nil {
		return fmt.Errorf("failed to verify GPU driver digest: %v", err)
	}

	cmds := [][]string{
		{"/sbin/modprobe", "drm_kms_helper"},
		{"/sbin/insmod", "/var/lib/nvidia/drivers/nvidia.ko"},
		{"/sbin/insmod", "/var/lib/nvidia/drivers/nvidia-uvm.ko"},
		{"/sbin/insmod", "/var/lib/nvidia/drivers/nvidia-modeset.ko"},
		{"/sbin/insmod", "/var/lib/nvidia/drivers/nvidia-drm.ko"},
	}

	for _, cmdArgs := range cmds {
		cmd := exec.Command("sudo", cmdArgs...)
		if out, err := cmd.CombinedOutput(); err != nil {
			di.logger.Info(fmt.Sprintf("failed to run command %v: %v, output: %s", cmdArgs, err, string(out)))
		}
	}

	if err = launchNvidiaPersistencedProcess(di.logger); err != nil {
		return fmt.Errorf("failed to start nvidia-persistenced process: %v", err)
	}

	nvidiaSmiVerifyCmd := NvidiaSmiOutputFunc()
	if err = verifyDriverInstallation(nvidiaSmiVerifyCmd); err != nil {
		return fmt.Errorf("failed to verify GPU driver installation: %v", err)
	}

	ccModeCmd := NvidiaSmiOutputFunc("conf-compute", "-f")
	devToolsCmd := NvidiaSmiOutputFunc("conf-compute", "-d")

	if gpuType == deviceinfo.B200 {
		topologyVerificationCmd := NvidiaSmiOutputFunc("topo", "-m")
		if err = verifyDriverInstallation(topologyVerificationCmd); err != nil {
			return fmt.Errorf("failed to verify Multi GPU topology: %v", err)
		}
	}

	ccEnabled, err := QueryCCMode(ccModeCmd, devToolsCmd)
	if err != nil {
		return fmt.Errorf("failed to check confidential compute mode status: %v", err)
	}
	// Explicitly need to set the GPU state to READY for GPUs with confidential compute mode ON.
	if ccEnabled == attest.GPUDeviceCCMode_ON {
		setGPUStateCmd := NvidiaSmiOutputFunc("conf-compute", "-srs", "1")
		if err = setGPUStateToReady(setGPUStateCmd); err != nil {
			return fmt.Errorf("failed to set the GPU state to ready: %v", err)
		}
	}

	di.logger.Info("GPU driver installation completed successfully")
	return nil
}

func verifyInstallerImageDigest(image containerd.Image, referenceDigest string) error {
	installerDigest := image.Target().Digest.String()
	if installerDigest != referenceDigest {
		return fmt.Errorf("cos_gpu_installer image digest verification failed - expected : %s, actual : %s", referenceDigest, installerDigest)
	}
	return nil
}

func verifyDriverDigest(driverFilePath, referenceDigest string) error {
	contentBytes, err := os.ReadFile(driverFilePath)
	if err != nil {
		return fmt.Errorf("failed to read the file %s, got error %v", driverFilePath, err)
	}
	checksum := sha256.Sum256(contentBytes)
	checksumHex := hex.EncodeToString(checksum[:])
	if checksumHex != referenceDigest {
		return fmt.Errorf("GPU driver digest verification failed - expected : %s, got : %s", referenceDigest, checksumHex)
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

func verifyDriverInstallation(nvidiaSmiVerifyCmd NvidiaSmiCmdOutput) error {
	if _, err := nvidiaSmiVerifyCmd(); err != nil {
		return fmt.Errorf("failed to verify GPU driver installation : %v", err)
	}
	return nil
}

func setGPUStateToReady(nvidiaSmiSetGPUStateCmd NvidiaSmiCmdOutput) error {
	if _, err := nvidiaSmiSetGPUStateCmd(); err != nil {
		return fmt.Errorf("failed to set the GPU state to ready: %v", err)
	}
	return nil
}

// QueryCCMode executes nvidia-smi to determine the current Confidential Computing (CC) mode status of the GPU.
// If DEVTOOLS mode is enabled, it would override CC mode as DEVTOOLS. DEVTOOLS mode would be enabled only when CC mode is ON.
func QueryCCMode(ccModeCmd, devToolsCmd NvidiaSmiCmdOutput) (attest.GPUDeviceCCMode, error) {
	ccMode := attest.GPUDeviceCCMode_UNSET
	ccModeOutput, err := ccModeCmd()
	if err != nil {
		return attest.GPUDeviceCCMode_UNSET, err
	}

	devToolsOutput, err := devToolsCmd()
	if err != nil {
		return attest.GPUDeviceCCMode_UNSET, err
	}

	if strings.Contains(string(ccModeOutput), "CC status: ON") {
		ccMode = attest.GPUDeviceCCMode_ON
	} else if strings.Contains(string(ccModeOutput), "CC status: OFF") {
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

// NvidiaSmiOutputFunc returns a function which executes the nvidia-smi command with the given arguments
// and returns the raw byte output and any error.
func NvidiaSmiOutputFunc(args ...string) NvidiaSmiCmdOutput {
	cmd := fmt.Sprintf("%s/bin/nvidia-smi", InstallationHostDir)
	return func() ([]byte, error) { return exec.Command(cmd, args...).Output() }
}
