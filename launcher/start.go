package launcher

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"cloud.google.com/go/compute/metadata"
	"cos.googlesource.com/cos/tools.git/src/cmd/cos_gpu_installer/deviceinfo"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/defaults"
	"github.com/containerd/containerd/namespaces"
	"github.com/google/go-tpm-tools/agent"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/launcher/internal/gpu"
	"github.com/google/go-tpm-tools/launcher/internal/logging"
	"github.com/google/go-tpm-tools/launcher/registryauth"
	"github.com/google/go-tpm-tools/launcher/spec"
	"github.com/google/go-tpm-tools/launcher/teeserver"
	"github.com/google/go-tpm-tools/verifier"
	"github.com/google/go-tpm-tools/verifier/fake"
	"github.com/google/go-tpm-tools/verifier/ita"
	"github.com/google/go-tpm-tools/verifier/util"
	"github.com/google/go-tpm/legacy/tpm2"
	"google.golang.org/api/option"
)

var expectedTPMDAParams = TPMDAParams{
	MaxTries:        0x20,    // 32 tries
	RecoveryTime:    0x1C20,  // 120 mins
	LockoutRecovery: 0x15180, // 24 hrs
}

// StartLauncher orchestrates the client creation, image pulling, attestation agent setup,
// and runs the ContainerRunner.
func StartLauncher(ctx context.Context, launchSpec spec.LaunchSpec, logger logging.Logger, workloadLogger logging.Logger, serialConsole *os.File, clientOpts ...option.ClientOption) error {
	containerdClient, err := containerd.New(defaults.DefaultAddress)
	if err != nil {
		return &RetryableError{Err: err}
	}
	defer containerdClient.Close()

	tpm, err := initTPM(launchSpec, logger)
	if err != nil {
		return err
	}
	if tpm != nil {
		defer tpm.Close()
	}

	mdsClient := metadata.NewClient(nil)
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

	googleClient, err := GoogleHTTPClient()
	if err != nil {
		return fmt.Errorf("failed to initialize Google root HTTP client: %v", err)
	}

	image, err := initImage(ctx, containerdClient, launchSpec, token, googleClient)
	if err != nil {
		return err
	}
	// Initialize verifier client and attest clients.
	attestClients, err := createAttestClients(ctx, launchSpec, logger, clientOpts...)
	if err != nil {
		return err
	}
	var verifierClient verifier.Client
	if launchSpec.ITAConfig.ITARegion != "" && !launchSpec.FakeVerifierEnabled {
		verifierClient = attestClients.ITA
	} else {
		verifierClient = attestClients.GCA
	}

	// Create principal fetcher.
	principalFetcherWithImpersonate := func(audience string) ([][]byte, error) {
		tokens, err := util.PrincipalFetcher(audience, mdsClient)
		if err != nil {
			return nil, err
		}
		for _, sa := range launchSpec.ImpersonateServiceAccounts {
			idToken, err := FetchImpersonatedToken(ctx, sa, audience, clientOpts...)
			if err != nil {
				return nil, fmt.Errorf("failed to get impersonated token for %v: %w", sa, err)
			}
			tokens = append(tokens, idToken)
		}
		return tokens, nil
	}

	// Create signature discovery client.
	sdClient := getSignatureDiscoveryClient(containerdClient, mdsClient, image.Target(), googleClient)

	// Create device ROTs and GpuAttester.
	var deviceROTs []agent.DeviceROT
	gpuAttester := gpu.NewNvidiaAttester(launchSpec.InstallGpuDriver)
	if launchSpec.InstallGpuDriver {
		deviceROTs = append(deviceROTs, gpuAttester)
	}

	// Create AttestationAgent.
	exps := agent.Experiments{
		EnableAttestationEvidence: launchSpec.Experiments.EnableAttestationEvidence,
		EnableGpuGcaSupport:       launchSpec.Experiments.EnableGpuGcaSupport,
		BcMode:                    launchSpec.Experiments.BcMode,
	}
	attestAgent, err := agent.CreateAttestationAgent(tpm, client.GceAttestationKeyECC, verifierClient, principalFetcherWithImpersonate, sdClient, exps, logger, deviceROTs, launchSpec.SignedImageRepos)
	if err != nil {
		return err
	}

	r, err := NewRunner(ctx, &RunnerConfig{
		ContainerdClient: containerdClient,
		Image:            image,
		AttestAgent:      attestAgent,
		GpuAttester:      gpuAttester,
		AttestClients:    attestClients,
		LaunchSpec:       launchSpec,
		Logger:           logger,
		WorkloadLogger:   workloadLogger,
		SerialConsole:    serialConsole,
	})
	if err != nil {
		return err
	}
	defer r.Close(ctx)

	return r.Run(ctx)
}

func initTPM(launchSpec spec.LaunchSpec, logger logging.Logger) (io.ReadWriteCloser, error) {
	if launchSpec.Experiments.BcMode {
		logger.Info("Running in BC mode, bypassing TPM initialization and checks.")
		return nil, nil
	}

	tpm, err := tpm2.OpenTPM("/dev/tpmrm0")
	if err != nil {
		return nil, &TPMOpenError{Err: err}
	}

	// check DA info, don't crash if failed
	daInfo, err := GetTPMDAInfo(tpm)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to get DA Info: %v", err))
	} else {
		if !daInfo.StartupClearOrderly {
			logger.Warn(fmt.Sprintf("Failed orderly startup. Avoid using instance reset. Instead, use instance stop/start. DA lockout counter incremented: LockoutCounter: %d / MaxAuthFail: %d", daInfo.LockoutCounter, daInfo.MaxTries))
		}

		if err := SetTPMDAParams(tpm, expectedTPMDAParams); err != nil {
			logger.Error(fmt.Sprintf("Failed to set DA params: %v", err))
		}

		daInfo, err := GetTPMDAInfo(tpm)
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to get DA Info: %v", err))
		} else {
			logger.Info(fmt.Sprintf("Updated TPM DA params: %+v", daInfo))
		}
	}

	// check AK (EK signing) cert
	gceAk, err := client.GceAttestationKeyECC(tpm)
	if err != nil {
		tpm.Close()
		return nil, &TPMInitError{Err: err}
	}
	defer gceAk.Close()

	if gceAk.Cert() == nil {
		tpm.Close()
		return nil, &TPMInitError{Err: errors.New("failed to find AKCert on this VM: try creating a new VM or contacting support")}
	}

	return tpm, nil
}

func createAttestClients(ctx context.Context, launchSpec spec.LaunchSpec, logger logging.Logger, clientOpts ...option.ClientOption) (teeserver.AttestClients, error) {
	attestClients := teeserver.AttestClients{}

	if launchSpec.FakeVerifierEnabled {
		fakeClient := fake.NewClient(nil)
		attestClients.GCA = fakeClient
		attestClients.ITA = fakeClient
	} else if launchSpec.ITAConfig.ITARegion != "" {
		itaClient, err := ita.NewClient(launchSpec.ITAConfig)
		if err != nil {
			return attestClients, fmt.Errorf("failed to create ITA client: %v", err)
		}
		attestClients.ITA = itaClient
	} else {
		gcaClient, err := util.NewRESTClient(ctx, launchSpec.GcaAddress, launchSpec.ProjectID, launchSpec.Region, clientOpts...)
		if err != nil {
			if !launchSpec.DisableGcaRefresh {
				return attestClients, fmt.Errorf("failed to create REST verifier client: %v", err)
			}
			logger.Info("Failed to create the GCA client, but GCA refresh is disabled so the launch will continue: %v", err)
			gcaClient = nil
		}
		attestClients.GCA = gcaClient
	}

	return attestClients, nil
}
