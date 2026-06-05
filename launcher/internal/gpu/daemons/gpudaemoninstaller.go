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

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/oci"
	"github.com/google/go-tpm-tools/launcher/internal/logging"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

const (
	// GuestGPUToolsImageRef is the image reference for guest GPU tools sidecar
	GuestGPUToolsImageRef = "guest-gpu-tools:latest"
	gpuToolsContainerID   = "guest-gpu-tools-container"
	gpuToolsSnapshotID    = "guest-gpu-tools-snapshot"
)

// RunGPUSidecar runs the GPU tools sidecar container in the background.
func RunGPUSidecar(ctx context.Context, cdClient *containerd.Client, logger logging.Logger) error {
	ctx = namespaces.WithNamespace(ctx, namespaces.Default)

	// Load required ib_umad module
	logger.Info("Loading ib_umad module...")
	ibUmadCmd := exec.Command("sudo", "/sbin/modprobe", "ib_umad")
	if out, err := ibUmadCmd.CombinedOutput(); err != nil {
		logger.Info(fmt.Sprintf("failed to run modprobe ib_umad: %v, output: %s", err, string(out)))
	}

	kernelVer, err := getKernelVersion()
	if err != nil {
		logger.Warn(fmt.Sprintf("failed to get kernel version: %v", err))
	}

	// Dynamic detection and load of GPU drivers
	nvidiaModules := []string{"nvidia", "nvidia-uvm", "nvidia-modeset", "nvidia-peermem"}
	for _, mod := range nvidiaModules {
		logger.Info(fmt.Sprintf("Loading %s module...", mod))
		cmd := exec.Command("sudo", "/sbin/modprobe", mod)
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
		cmd = exec.Command("sudo", "/sbin/insmod", modPath)
		if out, err := cmd.CombinedOutput(); err != nil {
			logger.Info(fmt.Sprintf("failed to run insmod %s: %v, output: %s", modPath, err, string(out)))
		}
	}

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

	// Clean up any existing guest GPU tools container
	if c, err := cdClient.LoadContainer(ctx, gpuToolsContainerID); err == nil {
		logger.Info("Deleting existing guest GPU tools container")
		if t, err := c.Task(ctx, nil); err == nil {
			t.Kill(ctx, syscall.SIGKILL)
			t.Delete(ctx)
		}
		c.Delete(ctx, containerd.WithSnapshotCleanup)
	}

	logger.Info(fmt.Sprintf("Locating guest GPU tools image: %s", GuestGPUToolsImageRef))
	image, err := cdClient.GetImage(ctx, GuestGPUToolsImageRef)
	if err != nil {
		logger.Info("Guest GPU tools image not found locally, building from Dockerfile...")
		daemonsDir := findDaemonsDir()
		if daemonsDir == "" {
			return fmt.Errorf("failed to find daemons directory containing Dockerfile")
		}

		logger.Info(fmt.Sprintf("Building guest GPU tools image from %s...", daemonsDir))
		buildCmd := exec.Command("sudo", "docker", "build", "-t", GuestGPUToolsImageRef, daemonsDir)
		if out, err := buildCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to build guest GPU tools image: %v, output: %s", err, string(out))
		}

		logger.Info("Exporting guest GPU tools image from docker and importing to containerd...")
		saveCmd := exec.Command("sudo", "docker", "save", GuestGPUToolsImageRef)
		stdout, err := saveCmd.StdoutPipe()
		if err != nil {
			return fmt.Errorf("failed to get stdout pipe for docker save: %v", err)
		}
		if err := saveCmd.Start(); err != nil {
			return fmt.Errorf("failed to start docker save: %v", err)
		}

		importedImages, err := cdClient.Import(ctx, stdout)
		if err != nil {
			saveCmd.Wait()
			return fmt.Errorf("failed to import guest GPU tools image: %v", err)
		}
		if err := saveCmd.Wait(); err != nil {
			return fmt.Errorf("docker save command failed: %v", err)
		}

		if len(importedImages) == 0 {
			return fmt.Errorf("imported zero images from docker save")
		}

		image, err = cdClient.GetImage(ctx, GuestGPUToolsImageRef)
		if err != nil {
			return fmt.Errorf("failed to get imported image from containerd: %v", err)
		}
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

func findDaemonsDir() string {
	paths := []string{
		"/usr/share/oem/gpu_daemons",
		"launcher/internal/gpu/daemons",
		"internal/gpu/daemons",
		"daemons",
		".",
	}
	for _, p := range paths {
		if _, err := os.Stat(filepath.Join(p, "Dockerfile")); err == nil {
			return p
		}
	}
	return ""
}
