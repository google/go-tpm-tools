package launcher

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"cloud.google.com/go/compute/metadata"
	"cos.googlesource.com/cos/tools.git/src/cmd/cos_gpu_installer/deviceinfo"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/defaults"
	"github.com/containerd/containerd/namespaces"
	"github.com/google/go-tpm-tools/launcher/internal/gpu"
	"github.com/google/go-tpm-tools/launcher/internal/logging"
	"github.com/google/go-tpm-tools/launcher/registryauth"
	"github.com/google/go-tpm-tools/launcher/spec"
	"google.golang.org/api/option"
)

// StartLauncher orchestrates the container creation and runs the ContainerRunner.
func StartLauncher(
	ctx context.Context,
	launchSpec spec.LaunchSpec,
	tpm io.ReadWriteCloser,
	logger logging.Logger,
	workloadLogger logging.Logger,
	mdsClient *metadata.Client,
	start time.Time,
	serialConsole *os.File,
	googleClient *http.Client,
	clientOpts ...option.ClientOption,
) error {
	logger.Info(fmt.Sprintf("Launch Spec: %+v", launchSpec.LogFriendly()))
	containerdClient, err := containerd.New(defaults.DefaultAddress)
	if err != nil {
		return &RetryableError{Err: err}
	}
	defer containerdClient.Close()

	token, err := registryauth.RetrieveAuthToken(ctx, mdsClient)
	if err != nil {
		logger.Info(fmt.Sprintf("failed to retrieve auth token: %v, using empty auth for image pulling", err))
	}
	ctx = namespaces.WithNamespace(ctx, namespaces.Default)

	if launchSpec.InstallGpuDriver {
		if launchSpec.Experiments.BcMode {
			logger.Info("gpu driver is pre-installed in BC mode")
		} else {
			installer := gpu.NewDriverInstaller(containerdClient, launchSpec, logger)
			err = installer.InstallGPUDrivers(ctx)
			if err != nil {
				return fmt.Errorf("failed to install gpu drivers: %v", err)
			}
		}
	} else {
		deviceInfo, _ := deviceinfo.GetGPUTypeInfo()
		if deviceInfo != deviceinfo.NO_GPU {
			logger.Error("GPU is attached, tee-install-gpu-driver is not set")
			return fmt.Errorf("failed to install GPU drivers: tee-install-gpu-driver must be set to true")
		}
	}

	logger.Info("Launch started", "duration_sec", time.Since(start).Seconds())

	image, err := initImage(ctx, containerdClient, launchSpec, token, googleClient)
	if err != nil {
		return err
	}

	r, err := NewRunner(ctx, &RunnerConfig{
		ContainerdClient: containerdClient,
		LaunchSpec:       launchSpec,
		MetadataClient:   mdsClient,
		TPM:              tpm,
		Logger:           logger,
		WorkloadLogger:   workloadLogger,
		SerialConsole:    serialConsole,
		GoogleClient:     googleClient,
		ClientOpts:       clientOpts,
		Image:            image,
	})
	if err != nil {
		return err
	}
	defer r.Close(ctx)

	return r.Run(ctx)
}
