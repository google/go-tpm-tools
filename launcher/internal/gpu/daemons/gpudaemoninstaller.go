// Package daemons contains logic to run guest GPU tools sidecar daemons.
package daemons

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/oci"
	"github.com/google/go-tpm-tools/launcher/internal/logging"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

const (
	// GuestGPUToolsImageRef is the image reference for guest GPU tools sidecar
	GuestGPUToolsImageRef = "docker.io/library/guest-gpu-tools:latest"
	// TODO(future): DistrolessGPUToolsImageRef is the future image reference for a distroless guest GPU tools sidecar
	// DistrolessGPUToolsImageRef = "docker.io/library/distroless-gpu-tools:latest"
	gpuToolsContainerID = "guest-gpu-tools-container"
	gpuToolsSnapshotID  = "guest-gpu-tools-snapshot"
)

// RunGPUSidecar runs the GPU tools sidecar container in the background.
// RunGPUSidecar runs the GPU tools sidecar container in the background.
func RunGPUSidecar(ctx context.Context, cdClient *containerd.Client, logger logging.Logger) error {
	ctx = namespaces.WithNamespace(ctx, namespaces.Default)

	setupHostDirectories(logger)

	if err := loadKernelModules(logger); err != nil {
		logger.Warn(fmt.Sprintf("kernel module loading encountered errors: %v", err))
	}

	startHostDaemons(logger)

	image, err := getOrCreateSidecarImage(ctx, cdClient, logger)
	if err != nil {
		return err
	}

	return launchSidecarContainer(ctx, cdClient, image, logger)
}

func setupHostDirectories(logger logging.Logger) {
	if err := os.MkdirAll("/run/nvidia", 0755); err != nil {
		logger.Warn(fmt.Sprintf("failed to create /run/nvidia directory: %v", err))
	}
	if err := os.MkdirAll("/var/run/nvidia-fabricmanager", 0755); err != nil {
		logger.Warn(fmt.Sprintf("failed to create /var/run/nvidia-fabricmanager directory: %v", err))
	}
}

func loadKernelModules(logger logging.Logger) error {
	// Load required ib_umad module
	logger.Info("Loading ib_umad module...")
	ibUmadCmd := exec.Command("sudo", "/sbin/modprobe", "ib_umad")
	if out, err := ibUmadCmd.CombinedOutput(); err != nil {
		logger.Info(fmt.Sprintf("failed to run modprobe ib_umad: %v, output: %s", err, string(out)))
	}

	kernelVer, err := getKernelVersion()
	if err != nil {
		return fmt.Errorf("failed to get kernel version: %w", err)
	}

	// Dynamic detection and load of GPU drivers
	nvidiaModules := []string{"nvidia", "nvidia-uvm", "nvidia-modeset"}
	if hasRDMA() {
		nvidiaModules = append(nvidiaModules, "nvidia-peermem")
	}
	for _, mod := range nvidiaModules {
		logger.Info(fmt.Sprintf("Loading %s module...", mod))

		// Build modprobe arguments. Inject GSP firmware flag for the main nvidia module.
		modprobeArgs := []string{"/sbin/modprobe", mod}
		if mod == "nvidia" {
			logger.Info("Enabling GSP GPU firmware offload for nvidia module")
			modprobeArgs = append(modprobeArgs, "NVreg_EnableGpuFirmware=1")
		}

		cmd := exec.Command("sudo", modprobeArgs...)
		out, err := cmd.CombinedOutput()
		if err == nil {
			logger.Info(fmt.Sprintf("Successfully loaded %s via modprobe", mod))
			continue
		}

		logger.Info(fmt.Sprintf("modprobe %s failed: %v, output: %s. Trying insmod...", mod, err, string(out)))
		modPath := findKernelModulePath(kernelVer, mod)
		if modPath == "" {
			logger.Info(fmt.Sprintf("Kernel module %s.ko not found in expected paths, skipping", mod))
			continue
		}
		logger.Info(fmt.Sprintf("Loading kernel module %s from %s", mod, modPath))

		// Build insmod arguments. Inject GSP firmware flag for the main nvidia module.
		insmodArgs := []string{"/sbin/insmod", modPath}
		if mod == "nvidia" {
			logger.Info("Enabling GSP GPU firmware offload for nvidia module")
			insmodArgs = append(insmodArgs, "NVreg_EnableGpuFirmware=1")
		}

		cmd = exec.Command("sudo", insmodArgs...)
		if out, err := cmd.CombinedOutput(); err != nil {
			logger.Info(fmt.Sprintf("failed to run insmod %s: %v, output: %s", modPath, err, string(out)))
		}
	}
	return nil
}

func startHostDaemons(logger logging.Logger) {
	// Start nvidia-persistenced daemon on the host if found
	persistencedCmd := findNvidiaHostBinary("nvidia-persistenced")
	if persistencedCmd != "" {
		logger.Info(fmt.Sprintf("Starting nvidia-persistenced: %s", persistencedCmd))
		cmd := exec.Command("sudo", persistencedCmd)
		if out, err := cmd.CombinedOutput(); err != nil {
			logger.Info(fmt.Sprintf("failed to start nvidia-persistenced: %v, output: %s", err, string(out)))
		}
	} else {
		logger.Warn("nvidia-persistenced binary not found on host")
	}

	// Trigger character devices creation (/dev/nvidia*)
	modprobeCmd := findNvidiaHostBinary("nvidia-modprobe")
	if modprobeCmd != "" {
		logger.Info(fmt.Sprintf("Triggering character devices creation with: %s", modprobeCmd))
		cmd := exec.Command("sudo", modprobeCmd, "-c", "0", "-u")
		if out, err := cmd.CombinedOutput(); err != nil {
			logger.Info(fmt.Sprintf("failed to run nvidia-modprobe: %v, output: %s", err, string(out)))
		}
	} else {
		logger.Warn("nvidia-modprobe binary not found on host")
	}

	// Verify GPU state with nvidia-smi
	smiCmd := findNvidiaHostBinary("nvidia-smi")
	if smiCmd != "" {
		logger.Info(fmt.Sprintf("Verifying hardware state with: %s", smiCmd))
		cmd := exec.Command("sudo", smiCmd)
		if out, err := cmd.CombinedOutput(); err != nil {
			logger.Info(fmt.Sprintf("failed to run nvidia-smi verification: %v, output: %s", err, string(out)))
		} else {
			logger.Info(fmt.Sprintf("NVIDIA SMI verification output:\n%s", string(out)))
		}
	} else {
		logger.Warn("nvidia-smi binary not found on host")
	}
}

func getOrCreateSidecarImage(ctx context.Context, cdClient *containerd.Client, logger logging.Logger) (containerd.Image, error) {
	logger.Info(fmt.Sprintf("Locating guest GPU tools image: %s", GuestGPUToolsImageRef))
	image, err := cdClient.GetImage(ctx, GuestGPUToolsImageRef)
	if err == nil {
		return image, nil
	}

	imageTarPath := findDaemonsTar()
	if imageTarPath == "" {
		return nil, fmt.Errorf("failed to find guest GPU tools image tar file")
	}

	logger.Info(fmt.Sprintf("Importing guest GPU tools image from %s...", imageTarPath))
	file, err := os.Open(imageTarPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open guest GPU tools image tar: %v", err)
	}
	defer file.Close()

	importedImages, err := cdClient.Import(ctx, file)
	if err != nil {
		return nil, fmt.Errorf("failed to import guest GPU tools image from tar: %v", err)
	}
	if len(importedImages) == 0 {
		return nil, fmt.Errorf("imported zero images from guest GPU tools image tar")
	}

	// Use the imported image name returned from containerd import
	image, err = cdClient.GetImage(ctx, importedImages[0].Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get imported image from containerd: %v", err)
	}

	return image, nil
}

func launchSidecarContainer(ctx context.Context, cdClient *containerd.Client, image containerd.Image, logger logging.Logger) error {
	// Clean up any existing guest GPU tools container
	if c, err := cdClient.LoadContainer(ctx, gpuToolsContainerID); err == nil {
		logger.Info("Deleting existing guest GPU tools container")
		if t, err := c.Task(ctx, nil); err == nil {
			t.Kill(ctx, syscall.SIGKILL)
			t.Delete(ctx)
		}
		c.Delete(ctx, containerd.WithSnapshotCleanup)
	}

	// Ensure the image is unpacked in containerd's snapshotter
	logger.Info("Unpacking guest GPU tools image...")
	if err := image.Unpack(ctx, containerd.DefaultSnapshotter); err != nil {
		return fmt.Errorf("failed to unpack guest GPU tools image: %v", err)
	}

	// Resolve the correct host driver directory
	hostDriverDir := "/var/lib/nvidia"
	if _, err := os.Stat("/opt/nvidia"); err == nil {
		hostDriverDir = "/opt/nvidia"
	}
	logger.Info(fmt.Sprintf("Using host GPU driver directory: %s", hostDriverDir))

	mounts := []specs.Mount{
		{
			Type:        "volume",
			Source:      "/dev",
			Destination: "/dev",
			Options:     []string{"rbind", "rw"},
		}, {
			Type:        "volume",
			Source:      hostDriverDir,
			Destination: "/opt/nvidia-host",
			Options:     []string{"rbind", "rw"},
		}, {
			Type:        "volume",
			Source:      "/run/nvidia",
			Destination: "/run/nvidia",
			Options:     []string{"rbind", "rw"},
		}, {
			Type:        "volume",
			Source:      "/var/run/nvidia-fabricmanager",
			Destination: "/var/run/nvidia-fabricmanager",
			Options:     []string{"rbind", "rw"},
		},
	}

	hostname, err := os.Hostname()
	if err != nil {
		logger.Error(fmt.Sprintf("cannot get hostname: %v", err))
	}

	container, err := cdClient.NewContainer(
		ctx,
		gpuToolsContainerID,
		containerd.WithImage(image),
		containerd.WithNewSnapshot(gpuToolsSnapshotID, image),
		containerd.WithNewSpec(oci.WithImageConfig(image),
			oci.WithPrivileged,
			oci.WithAllDevicesAllowed,
			oci.WithHostDevices,
			oci.WithMounts(mounts),
			oci.WithHostNamespace(specs.NetworkNamespace),
			oci.WithHostHostsFile,
			oci.WithHostResolvconf,
			oci.WithEnv([]string{fmt.Sprintf("HOSTNAME=%s", hostname)})))
	if err != nil {
		return fmt.Errorf("failed to create guest GPU tools container: %v", err)
	}

	// Create and start task in background (detached)
	task, err := container.NewTask(ctx, cio.NewCreator(cio.WithStdio))
	if err != nil {
		container.Delete(ctx, containerd.WithSnapshotCleanup)
		return fmt.Errorf("failed to create guest GPU tools task: %v", err)
	}

	logger.Info("Starting guest GPU tools sidecar container task in background...")
	if err := task.Start(ctx); err != nil {
		task.Delete(ctx)
		container.Delete(ctx, containerd.WithSnapshotCleanup)
		return fmt.Errorf("failed to start guest GPU tools task: %v", err)
	}

	logger.Info("Guest GPU tools sidecar container successfully started")
	return nil
}

func getKernelVersion() (string, error) {
	kernelVerBytes, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(kernelVerBytes)), nil
}

func findKernelModulePath(kernelVer, moduleName string) string {
	if kernelVer != "" {
		nvidiaDir := fmt.Sprintf("/lib/modules/%s/nvidia", kernelVer)
		if files, err := os.ReadDir(nvidiaDir); err == nil {
			for _, file := range files {
				if file.IsDir() {
					p := fmt.Sprintf("/lib/modules/%s/nvidia/%s/%s.ko", kernelVer, file.Name(), moduleName)
					if _, err := os.Stat(p); err == nil {
						return p
					}
				}
			}
		}
	}
	p2 := fmt.Sprintf("/var/lib/nvidia/drivers/%s.ko", moduleName)
	if _, err := os.Stat(p2); err == nil {
		return p2
	}
	return ""
}

func findNvidiaHostBinary(name string) string {
	p1 := fmt.Sprintf("/var/lib/nvidia/bin/%s", name)
	if _, err := os.Stat(p1); err == nil {
		return p1
	}
	if files, err := os.ReadDir("/opt/nvidia"); err == nil {
		for _, file := range files {
			if file.IsDir() {
				p := fmt.Sprintf("/opt/nvidia/%s/bin/%s", file.Name(), name)
				if _, err := os.Stat(p); err == nil {
					return p
				}
			}
		}
	}
	return ""
}

func findDaemonsTar() string {
	paths := []string{
		"/usr/share/oem/gpu_daemons",
		"launcher/internal/gpu/daemons",
		"internal/gpu/daemons",
		"daemons",
		".",
	}
	for _, p := range paths {
		tarPath := filepath.Join(p, "image.tar")
		if _, err := os.Stat(tarPath); err == nil {
			return tarPath
		}
	}
	return ""
}

func hasRDMA() bool {
	files, err := os.ReadDir("/sys/class/infiniband")
	if err != nil {
		return false
	}
	return len(files) > 0
}

const gpuReadyPath = "/run/nvidia/gpu-ready"

// WaitForGPUServices blocks until the sidecar daemon writes the readiness file.
func WaitForGPUServices(ctx context.Context) error {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for GPU driver initialization: %w", ctx.Err())
		case <-ticker.C:
			if _, err := os.Stat(gpuReadyPath); err == nil {
				return nil
			}
		}
	}
}

// RunGPUSidecarDistroless runs the future optimized distroless GPU tools sidecar image.
//
// TODO(future): Implement this method to launch a container task based on gcr.io/distroless/cc-debian12.
// Building and running a distroless container allows us to:
//  1. Decouple dependencies (like glibc and dynamic linkers) to prevent conflicts with the host OS.
//  2. Drastically reduce the sidecar image footprint (from ~200MB+ down to ~30MB).
//  3. Eliminate VM-bootup build/export delays (reducing bootup GPU setup duration from ~71s to <1s)
//     by pre-building and caching the container image in the guest image local containerd repository.
// func RunGPUSidecarDistroless(ctx context.Context, cdClient *containerd.Client, logger logging.Logger) error {
// 	return fmt.Errorf("unimplemented: RunGPUSidecarDistroless is a future optimization placeholder")
// }

// RunGPUSidecarChroot runs GPU daemons natively inside an isolated chroot jail filesystem.
//
// TODO(future): Implement this method to run GPU daemons natively inside a chroot jail at
// /opt/nvidia/sidecar_root/ or in a dedicated mount namespace (unshare -m).
// This serves as an alternative to containerd tasks, bypassing OCI/containerd runtime overhead
// (cgroups, networking, containerd database tasks) while still ensuring dynamic library decoupling.
// func RunGPUSidecarChroot(ctx context.Context, logger logging.Logger) error {
// 	return fmt.Errorf("unimplemented: RunGPUSidecarChroot is a future optimization placeholder")
// }
