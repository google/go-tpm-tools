package launcher

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
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
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
)

var expectedTPMDAParams = TPMDAParams{
	MaxTries:        0x20,    // 32 tries
	RecoveryTime:    0x1C20,  // 120 mins
	LockoutRecovery: 0x15180, // 24 hrs
}

// StartLauncher orchestrates the client creation, image pulling, attestation agent setup,
// and runs the ContainerRunner.
func StartLauncher(ctx context.Context, launchSpec spec.LaunchSpec, logger logging.Logger, workloadLogger logging.Logger, serialConsole *os.File, pinnedClient *http.Client, googleClient *http.Client) error {
	if pinnedClient == nil {
		return errors.New("pinnedClient must be non-nil")
	}

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

	image, err := initImage(ctx, containerdClient, launchSpec, token, pinnedClient)
	if err != nil {
		return err
	}

	// googleClient is an authenticated HTTP client (OAuth2 ADC credentials) built on top
	// of the pinned transport. Used for GCA verifier client creation and SA impersonation.
	attestClients, err := createAttestClients(ctx, launchSpec, logger, googleClient)
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
			idToken, err := FetchImpersonatedToken(ctx, sa, audience, option.WithHTTPClient(googleClient))
			if err != nil {
				return nil, fmt.Errorf("failed to get impersonated token for %v: %w", sa, err)
			}
			tokens = append(tokens, idToken)
		}
		return tokens, nil
	}

	// Create signature discovery client.
	sdClient := getSignatureDiscoveryClient(containerdClient, mdsClient, image.Target(), pinnedClient)

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

// AuthenticatedGoogleHTTPClient creates an HTTP client configured with OAuth2 token credentials
// (via Application Default Credentials) on top of an existing pinned Google Root CA transport.
func AuthenticatedGoogleHTTPClient(ctx context.Context, pinnedClient *http.Client) (*http.Client, error) {
	if pinnedClient == nil {
		return nil, errors.New("pinnedClient must be non-nil")
	}

	ts, err := google.DefaultTokenSource(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return nil, fmt.Errorf("failed to get default token source: %w", err)
	}

	return &http.Client{
		Transport: &oauth2.Transport{
			Source: ts,
			Base:   pinnedClient.Transport,
		},
	}, nil
}

func validateAttestHTTPClient(googleClient *http.Client) error {
	if googleClient == nil {
		return errors.New("googleClient must be non-nil")
	}
	oauthTransport, ok := googleClient.Transport.(*oauth2.Transport)
	if !ok || oauthTransport.Source == nil {
		return errors.New("missing OAuth2 token credentials")
	}
	baseTransport, ok := oauthTransport.Base.(*http.Transport)
	if !ok || baseTransport.TLSClientConfig == nil || baseTransport.TLSClientConfig.RootCAs == nil {
		return errors.New("missing pinned Google Root CAs")
	}
	return nil
}

// createAttestClients initializes verifier clients (GCA/ITA).
// When DisableGcaRefresh is false, googleClient must be configured with both OAuth2 token credentials
// and Google Root CA certificate pinning.
func createAttestClients(ctx context.Context, launchSpec spec.LaunchSpec, logger logging.Logger, googleClient *http.Client) (teeserver.AttestClients, error) {
	attestClients := teeserver.AttestClients{}

	if !launchSpec.DisableGcaRefresh {
		if err := validateAttestHTTPClient(googleClient); err != nil {
			return attestClients, fmt.Errorf("failed to create REST verifier client: %v", err)
		}
	}

	if launchSpec.FakeVerifierEnabled {
		fakeClient := fake.NewClient(nil)
		attestClients.GCA = fakeClient
		attestClients.ITA = fakeClient
		return attestClients, nil
	}
	if launchSpec.ITAConfig.ITARegion != "" {
		itaClient, err := ita.NewClient(launchSpec.ITAConfig)
		if err != nil {
			return attestClients, fmt.Errorf("failed to create ITA client: %v", err)
		}
		attestClients.ITA = itaClient
		return attestClients, nil
	}

	gcaClient, err := util.NewRESTClient(ctx, launchSpec.GcaAddress, launchSpec.ProjectID, launchSpec.Region, option.WithHTTPClient(googleClient))
	if err != nil {
		if !launchSpec.DisableGcaRefresh {
			return attestClients, fmt.Errorf("failed to create REST verifier client: %v", err)
		}
		logger.Info("Failed to create the GCA client, but GCA refresh is disabled so the launch will continue: %v", err)
		gcaClient = nil
	}
	attestClients.GCA = gcaClient
	return attestClients, nil
}
