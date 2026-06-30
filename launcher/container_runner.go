// Package launcher contains functionalities to start a measured workload
package launcher

import (
	"context"
	cryt "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"cloud.google.com/go/compute/metadata"
	attestationpb "github.com/GoogleCloudPlatform/confidential-space/server/proto/gen/attestation"
	"github.com/cenkalti/backoff/v4"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/oci"
	"github.com/containerd/containerd/remotes"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/go-tpm-tools/agent"
	"github.com/google/go-tpm-tools/cel"
	"github.com/google/go-tpm-tools/client"
	keymanager "github.com/google/go-tpm-tools/keymanager/km_common/proto"
	workloadservice "github.com/google/go-tpm-tools/keymanager/workload_service"
	"github.com/google/go-tpm-tools/launcher/internal/gpu"
	"github.com/google/go-tpm-tools/launcher/internal/healthmonitoring/nodeproblemdetector"
	"github.com/google/go-tpm-tools/launcher/internal/logging"
	"github.com/google/go-tpm-tools/launcher/internal/signaturediscovery"
	"github.com/google/go-tpm-tools/launcher/launcherfile"
	"github.com/google/go-tpm-tools/launcher/registryauth"
	"github.com/google/go-tpm-tools/launcher/spec"
	"github.com/google/go-tpm-tools/launcher/teeserver"
	"github.com/google/go-tpm-tools/verifier"
	ociverifier "github.com/google/go-tpm-tools/verifier/oci"
	"github.com/google/go-tpm-tools/verifier/fake"
	"github.com/google/go-tpm-tools/verifier/ita"
	"github.com/google/go-tpm-tools/verifier/util"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/oauth2"
	"google.golang.org/protobuf/proto"
	"golang.org/x/sync/errgroup"
)

// ContainerRunner contains information about the container settings
type ContainerRunner struct {
	container     []containerd.Container
	launchSpec    spec.LaunchSpec
	attestAgent   agent.AttestationAgent
	logger        logging.Logger
	gpuAttester   gpu.Attester
	serialConsole *os.File
	powerButton   *powerButtonListener // Populated only for a hardened image
}

const tokenFileTmp = ".token.tmp"

const teeServerSocket = "teeserver.sock"
const keyManagerSocket = "kmaserver.sock"

// Since we only allow one container on a VM, using a deterministic id is probably fine
const (
	containerID = "tee-container"
	snapshotID  = "tee-snapshot"
)

const (
	nofile = 131072 // Max number of file descriptor
)

const (
	// defaultRefreshMultiplier is a multiplier on the current token expiration
	// time, at which the refresher goroutine will collect a new token.
	// defaultRefreshMultiplier+defaultRefreshJitter should be <1.
	defaultRefreshMultiplier = 0.8
	// defaultRefreshJitter is a random component applied additively to the
	// refresh multiplier. The refresher will wait for some time in the range
	// [defaultRefreshMultiplier-defaultRefreshJitter, defaultRefreshMultiplier+defaultRefreshJitter]
	defaultRefreshJitter = 0.1
)

// Default OOM score for a CS container.
const defaultOOMScore = 1000

// NewRunner returns a runner.
func NewRunner(ctx context.Context, cdClient *containerd.Client, token oauth2.Token, launchSpec spec.LaunchSpec, mdsClient *metadata.Client, tpm io.ReadWriteCloser, logger logging.Logger, serialConsole *os.File) (*ContainerRunner, error) {
	images, err := pullImages(ctx, cdClient, launchSpec, token)
	if err != nil {
		return nil, err
	}

	var createdContainers []containerd.Container
	var nvidiaAttester gpu.Attester
	var deviceROTs []agent.DeviceROT

	for i, cSpec := range launchSpec.Containers {
		img := images[i]
		var c containerd.Container

		cID := containerID // "tee-container"
		sID := snapshotID  // "tee-snapshot"
		if i > 0 {
			cID = fmt.Sprintf("%s-%d", containerID, i)
			sID = fmt.Sprintf("%s-%d", snapshotID, i)
		}
		
		//Delete existing container if it exists( using the dynamic cID)
		if existingContainer, err := cdClient.LoadContainer(ctx, cID); err == nil {
			existingContainer.Delete(ctx, containerd.WithSnapshotCleanup)
		}

		var mounts []specs.Mount
		for _,lsMnt := range cSpec.Mounts {
			mounts = append(mounts, lsMnt.SpecsMount())
		}
		mounts = appendTokenMounts(mounts)

		var cgroupOpts []oci.SpecOpts
		if launchSpec.CgroupNamespace {
			mounts = appendCgroupRw(mounts)
			cgroupOpts = []oci.SpecOpts{
				oci.WithNamespacedCgroup(),
				oci.WithLinuxNamespace(specs.LinuxNamespace{Type: specs.CgroupNamespace}),
			}
		}

		envs, err := formatEnvVars(cSpec.Envs)
		if err != nil {
			return nil, err
		}

		logger.Info("Preparing Container Runner",
			"container_name", cSpec.Name,
			"operator_input_image_ref", img.Name(),
			"image_digest", img.Target().Digest,
			"operator_override_env_vars", envs,
			"operator_override_cmd", cSpec.Cmd,
		)
		
		imageConfig, err := getImageConfig(ctx, img)
		if err != nil {
			return nil, err
		}
		
		logger.Info(fmt.Sprintf("Exposed Ports for container %q (cID: %s):             : %v\n",cSpec.Name, cID, imageConfig.ExposedPorts))
		if err := setupFirewall(cSpec, imageConfig); err != nil {
			return nil, err
		}

		logger.Info(fmt.Sprintf("Image Labels for container %q (cID: %s):             : %v\n",cSpec.Name, cID, imageConfig.Labels))
		launchPolicy, err := spec.GetLaunchPolicy(imageConfig.Labels, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to parse image Launch Policy for container %q (cID: %s): %v: contact the image author", cSpec.Name, cID, err)
		}

		if err := launchPolicy.Verify(launchSpec); err != nil {
			return nil, err
		}

		logger.Info(fmt.Sprintf("Launch Policy              : %+v\n", launchPolicy))
		
		if imageConfigDescriptor, err := img.Config(ctx); err != nil {
			logger.Error(err.Error())
		} else {
			logger.Info("Retrieved image config",
				"image_id", imageConfigDescriptor.Digest,
				"image_annotations", imageConfigDescriptor.Annotations,
			)
		}

		hostname, err := os.Hostname()
		if err != nil {
			return nil, &RetryableError{fmt.Errorf("cannot get hostname for container %q (cID: %s): [%w]",cSpec.Name, cID, err)}
		}
	
		rlimits := []specs.POSIXRlimit{{
			Type: "RLIMIT_NOFILE",
			Hard: nofile,
			Soft: nofile,
		}}
		
		specOpts := []oci.SpecOpts{
			oci.WithImageConfigArgs(img, cSpec.Cmd),
			oci.WithEnv(envs),
			oci.WithMounts(mounts),
			// following 4 options are here to allow the container to have
			// the host network (same effect as --net-host in ctr command)
			oci.WithHostHostsFile,
			oci.WithHostResolvconf,
			oci.WithHostNamespace(specs.NetworkNamespace),
			oci.WithEnv([]string{fmt.Sprintf("HOSTNAME=%s", hostname)}),
			oci.WithAddedCapabilities(cSpec.AddedCapabilities),
			withRlimits(rlimits),
			withOOMScoreAdj(defaultOOMScore),
		}

		if launchSpec.DevShmSize != 0 {
			specOpts = append(specOpts, oci.WithDevShmSize(launchSpec.DevShmSize))
		}
		specOpts = append(specOpts, cgroupOpts...)

		//GPU Attester (only need to initialize it once
		//but we apply mounts to all containers if driver is installed)
		if launchSpec.InstallGpuDriver {
			if nvidiaAttester == nil {
				nvidiaAttester = gpu.NewNvidiaAttester(launchSpec.InstallGpuDriver)
			}
			gpuMounts := []specs.Mount{
				{
					Type:        "volume",
					Source:      fmt.Sprintf("%s/lib64", gpu.InstallationHostDir),
					Destination: fmt.Sprintf("%s/lib64", gpu.InstallationContainerDir),
					Options:     []string{"rbind", "rw"},
				}, {
					Type:        "volume",
					Source:      fmt.Sprintf("%s/bin", gpu.InstallationHostDir),
					Destination: fmt.Sprintf("%s/bin", gpu.InstallationContainerDir),
					Options:     []string{"rbind", "rw"},
				},
			}
			specOpts = append(specOpts, oci.WithMounts(gpuMounts))
	
			// /dev/nvidia-caps/* will not be listed here and will not be passed to
			// the container workload
			//
			// following devices should be listed:
			// /dev/nvidiactl
			// /dev/nvidia-uvm
			// /dev/nvidia-uvm-tools
			// /dev/nvidia{0,1,2,...}
			// /dev/nvidia-modeset
			gpuDeviceFiles, err := listFilesWithPrefix("/dev", "nvidia")
			if err != nil {
				return nil, fmt.Errorf("failed to list nvidia devices: [%w]", err)
			}
	
			for _, deviceFile := range gpuDeviceFiles {
				logger.Info(fmt.Sprintf("Detected nvidia device : %s", deviceFile))
				specOpts = append(specOpts, oci.WithDevices(deviceFile, deviceFile, "crw-rw-rw-"))
			}
			if len(deviceROTs) == 0 {
				deviceROTs = append(deviceROTs, nvidiaAttester)
			}
		}
	
		c, err = cdClient.NewContainer(
			ctx,
			cID,
			containerd.WithImage(img),
			containerd.WithNewSnapshot(sID, img),
			containerd.WithNewSpec(specOpts...),
		)
		if err != nil {
			if c != nil {
				c.Delete(ctx, containerd.WithSnapshotCleanup)
			}
			return nil, &RetryableError{fmt.Errorf("failed to create a container %s: [%w]", cID, err)}
		}

		containerSpec, err := c.Spec(ctx)
		if err != nil {
			// Clean up container since we can't get its spec
			c.Delete(ctx, containerd.WithSnapshotCleanup)
			return nil, &RetryableError{err}
		}
	
		// Container process Args length should be strictly longer than the Cmd
		// override length set by the operator, as we want the Entrypoint filed
		// to be mandatory for the image.
		// Roughly speaking, Args = Entrypoint + Cmd
		if len(containerSpec.Process.Args) <= len(cSpec.Cmd) {
			// Clean up container since we can't get its spec
			c.Delete(ctx, containerd.WithSnapshotCleanup)
			return nil,
				fmt.Errorf("length of Args [%d] is shorter or equal to the length of the given Cmd [%d] for container %q, maybe the Entrypoint is set to empty in the image?",
					len(containerSpec.Process.Args), len(cSpec.Cmd), cSpec.Name)
		}
		
		createdContainers = append(createdContainers, c)
	}


	if launchSpec.MonitoringEnabled == spec.All && !launchSpec.Experiments.EnableHealthMonitoring {
		logger.Info("Health Monitoring experiment is not enabled - falling back to memory-only.")
		if err := enableMonitoring(spec.MemoryOnly, logger); err != nil {
			return nil, err
		}
	} else {
		if err := enableMonitoring(launchSpec.MonitoringEnabled, logger); err != nil {
			return nil, err
		}
	}




	principalFetcherWithImpersonate := func(audience string) ([][]byte, error) {
		tokens, err := util.PrincipalFetcher(audience, mdsClient)
		if err != nil {
			return nil, err
		}

		// Fetch impersonated ID tokens.
		for _, sa := range launchSpec.ImpersonateServiceAccounts {
			idToken, err := FetchImpersonatedToken(ctx, sa, audience)
			if err != nil {
				return nil, fmt.Errorf("failed to get impersonated token for %v: %w", sa, err)
			}

			tokens = append(tokens, idToken)
		}
		return tokens, nil
	}

	asAddr := launchSpec.GcaAddress

	var verifierClient verifier.Client
	if launchSpec.FakeVerifierEnabled {
		verifierClient = fake.NewClient(nil)
	} else if launchSpec.ITAConfig.ITARegion == "" {
		gcaClient, err := util.NewRESTClient(ctx, asAddr, launchSpec.ProjectID, launchSpec.Region)
		if err != nil {
			if !launchSpec.DisableGcaRefresh {
				return nil, fmt.Errorf("failed to create REST verifier client: %v", err)
			}
			// If GCA refresh is disabled, swallow the error and continue.
			logger.Info("Failed to create the GCA client for attestation agent, this is not necessarily blocking because GCA refresh is disabled so the launch will continue: %v", err)
			gcaClient = nil
		}

		verifierClient = gcaClient
	}

	sdClient := &multiImageSignatureFetcher{
		images: 		images,
		cdClient:		cdClient,
		mdsClient:	mdsClient,
	}

	exps := agent.Experiments{
		EnableAttestationEvidence: launchSpec.Experiments.EnableAttestationEvidence,
		EnableGpuGcaSupport:       launchSpec.Experiments.EnableGpuGcaSupport,
		BcMode:                    launchSpec.Experiments.BcMode,
	}
	attestAgent, err := agent.CreateAttestationAgent(tpm, client.GceAttestationKeyECC, verifierClient, principalFetcherWithImpersonate, sdClient, exps, logger, deviceROTs, launchSpec.SignedImageRepos)
	if err != nil {
		return nil, err
	}

	var powerButton *powerButtonListener
	if launchSpec.Hardened {
		powerButton, err = newPowerButtonListener(logger)
		if err != nil {
			logger.Error(err.Error())
		}
	}

	return &ContainerRunner{
		createdContainers,
		launchSpec,
		attestAgent,
		logger,
		nvidiaAttester,
		serialConsole,
		powerButton,
	}, nil
}

func enableMonitoring(enabled spec.MonitoringType, logger logging.Logger) error {
	if enabled != spec.None {
		logger.Info("Health Monitoring is enabled by the VM operator")

		if enabled == spec.All {
			logger.Info("All health monitoring metrics enabled")
			if err := nodeproblemdetector.EnableAllConfig(); err != nil {
				logger.Error("Failed to enable full monitoring config: %v", err)
				return err
			}
		} else if enabled == spec.MemoryOnly {
			logger.Info("memory/bytes_used enabled")
		}

		if err := nodeproblemdetector.StartService(logger); err != nil {
			logger.Error(err.Error())
			return err
		}
	} else {
		logger.Info("Health Monitoring is disabled")
	}

	return nil
}

func getSignatureDiscoveryClient(cdClient *containerd.Client, mdsClient *metadata.Client, imageDesc v1.Descriptor) signaturediscovery.Fetcher {
	resolverFetcher := func(ctx context.Context) (remotes.Resolver, error) {
		return registryauth.RefreshResolver(ctx, mdsClient)
	}
	imageFetcher := func(ctx context.Context, imageRef string, opts ...containerd.RemoteOpt) (containerd.Image, error) {
		image, err := pullImageWithRetries(
			func() (containerd.Image, error) {
				return cdClient.Pull(ctx, imageRef, opts...)
			},
			pullImageBackoffPolicy,
		)
		if err != nil {
			return nil, fmt.Errorf("cannot pull signature objects from the signature image [%s]: %w", imageRef, err)
		}
		return image, nil
	}
	return signaturediscovery.New(imageDesc, resolverFetcher, imageFetcher)
}

// formatEnvVars formats the environment variables to the oci format
func formatEnvVars(envVars []spec.EnvVar) ([]string, error) {
	var result []string
	for _, envVar := range envVars {
		ociFormat, err := cel.FormatEnvVar(envVar.Name, envVar.Value)
		if err != nil {
			return nil, fmt.Errorf("failed to format env var: %v", err)
		}
		result = append(result, ociFormat)
	}
	return result, nil
}

// appendTokenMounts appends the default mount specs for the OIDC token
func appendTokenMounts(mounts []specs.Mount) []specs.Mount {
	m := specs.Mount{}
	m.Destination = launcherfile.ContainerRuntimeMountPath
	m.Type = "bind"
	m.Source = launcherfile.HostTmpPath
	m.Options = []string{"rbind", "ro"}

	return append(mounts, m)
}

func (r *ContainerRunner) measureCELEvents(ctx context.Context) error {
	if err := r.measureContainerClaims(ctx); err != nil {
		return fmt.Errorf("failed to measure container claims: %v", err)
	}

	if err := r.measureGPUAttestationEvidence(); err != nil {
		return fmt.Errorf("failed to measure GPU claims: %v", err)
	}

	if err := r.measureMemoryMonitor(); err != nil {
		return fmt.Errorf("failed to measure memory monitoring state: %v", err)
	}

	separator := cel.CosTlv{
		EventType:    cel.LaunchSeparatorType,
		EventContent: nil, // Success
	}
	return r.attestAgent.MeasureEvent(separator)
}

// measureContainerClaims will measure various container claims into the COS
// eventlog in the AttestationAgent.
func (r *ContainerRunner) measureContainerClaims(ctx context.Context) error {
	for i,c := range r.container {
		cSpec := r.launchSpec.Containers[i]

		image, err := c.Image(ctx)
		if err != nil {
			return err
		}

		if err := r.attestAgent.MeasureEvent(cel.CosTlv{EventType: cel.ImageRefType, EventContent: []byte(image.Name())}); err != nil {
			return err
		}
		
		if err := r.attestAgent.MeasureEvent(cel.CosTlv{EventType: cel.ImageDigestType, EventContent: []byte(image.Target().Digest)}); err != nil {
			return err
		}
		if err := r.attestAgent.MeasureEvent(cel.CosTlv{EventType: cel.RestartPolicyType, EventContent: []byte(cSpec.RestartPolicy)}); err != nil {
			return err
		}
		if imageConfigDescriptor, err := image.Config(ctx); err == nil { // if NO error
			if err := r.attestAgent.MeasureEvent(cel.CosTlv{EventType: cel.ImageIDType, EventContent: []byte(imageConfigDescriptor.Digest)}); err != nil {
				return err
			}
		}

		containerSpec, err := c.Spec(ctx)
		if err != nil {
			return err
		}
		
		for _, arg := range containerSpec.Process.Args {
			if err := r.attestAgent.MeasureEvent(cel.CosTlv{EventType: cel.ArgType, EventContent: []byte(arg)}); err != nil {
				return err
			}
		}
		for _, env := range containerSpec.Process.Env {
			if err := r.attestAgent.MeasureEvent(cel.CosTlv{EventType: cel.EnvVarType, EventContent: []byte(env)}); err != nil {
				return err
			}
		}

		// Measure the input overridden Env Vars and Args separately, these should be subsets of the Env Vars and Args above.
		envs, err := formatEnvVars(cSpec.Envs)
		if err != nil {
			return err
		}
		for _, env := range envs {
			if err := r.attestAgent.MeasureEvent(cel.CosTlv{EventType: cel.OverrideEnvType, EventContent: []byte(env)}); err != nil {
				return err
			}
		}
		for _, arg := range cSpec.Cmd {
			if err := r.attestAgent.MeasureEvent(cel.CosTlv{EventType: cel.OverrideArgType, EventContent: []byte(arg)}); err != nil {
				return err
			}
		}
	}
	return nil
}

// measureGPUAttestationEvidence will measure GPU attestation claims into the COS
// eventlog in the AttestationAgent.
func (r *ContainerRunner) measureGPUAttestationEvidence() error {
	if r.gpuAttester == nil {
		return nil
	}

	nonce := make([]byte, 32)
	if _, err := cryt.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate random nonce: %v", err)
	}

	evidence, err := r.gpuAttester.Attest(nonce)
	if err != nil {
		return fmt.Errorf("failed to collect GPU evidence: %w", err)
	}

	gpuEvidence, ok := evidence.(*attestationpb.NvidiaAttestationReport)
	if !ok {
		return fmt.Errorf("unexpected evidence type: %T", evidence)
	}

	evidenceBytes, err := proto.Marshal(gpuEvidence)
	if err != nil {
		return fmt.Errorf("failed to marshal GPU evidence: %w", err)
	}

	event := cel.CosTlv{
		EventType:    cel.GPUDeviceAttestationBindingType,
		EventContent: evidenceBytes,
	}
	if err := r.attestAgent.MeasureEvent(event); err != nil {
		return fmt.Errorf("failed to measure GPU attestation: %w", err)
	}

	if err := r.gpuAttester.EnableReadyState(); err != nil {
		return fmt.Errorf("failed to set GPU ready state: %w", err)
	}
	r.logger.Info("Successfully measured GPU device attestation binding event and set GPU state to ready")
	return nil
}

// measureMemoryMonitor will measure memory monitoring claims into the COS
// eventlog in the AttestationAgent.
func (r *ContainerRunner) measureMemoryMonitor() error {
	var enabled uint8
	if r.launchSpec.MonitoringEnabled == spec.MemoryOnly {
		enabled = 1
	}
	if err := r.attestAgent.MeasureEvent(cel.CosTlv{EventType: cel.MemoryMonitorType, EventContent: []byte{enabled}}); err != nil {
		return err
	}
	r.logger.Info("Successfully measured memory monitoring event")
	return nil
}

// Retrieves the default OIDC token from the attestation service, and returns how long
// to wait before attemping to refresh it.
// The token file will be written to a tmp file and then renamed.
func (r *ContainerRunner) refreshToken(ctx context.Context) (time.Duration, error) {
	if err := r.attestAgent.Refresh(ctx); err != nil {
		return 0, fmt.Errorf("failed to refresh attestation agent: %v", err)
	}

	// request a default token
	token, err := r.attestAgent.Attest(ctx, agent.AttestAgentOpts{DeviceReportOpts: &agent.DeviceReportOpts{EnableRuntimeGPUAttestation: true}})
	if err != nil {
		return 0, fmt.Errorf("failed to retrieve attestation service token: %v", err)
	}

	// Get token expiration.
	claims := &jwt.RegisteredClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(string(token), claims)
	if err != nil {
		return 0, fmt.Errorf("failed to parse token: %w", err)
	}

	now := time.Now()
	if !now.Before(claims.ExpiresAt.Time) {
		return 0, errors.New("token is expired")
	}

	// Write to a temp file first.
	tmpTokenPath := path.Join(launcherfile.HostTmpPath, tokenFileTmp)
	if err = os.WriteFile(tmpTokenPath, token, 0644); err != nil {
		return 0, fmt.Errorf("failed to write a tmp token file: %v", err)
	}

	// Rename the temp file to the token file (to avoid race conditions).
	if err = os.Rename(tmpTokenPath, path.Join(launcherfile.HostTmpPath, launcherfile.AttestationVerifierTokenFilename)); err != nil {
		return 0, fmt.Errorf("failed to rename the token file: %v", err)
	}

	// Print out the claims in the jwt payload
	mapClaims := jwt.MapClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(string(token), mapClaims)
	if err != nil {
		return 0, fmt.Errorf("failed to parse token: %w", err)
	}

	r.logger.Info("successfully refreshed attestation token", "token", mapClaims)

	return getNextRefreshFromExpiration(time.Until(claims.ExpiresAt.Time), rand.Float64()), nil
}

// ctx must be a cancellable context.
func (r *ContainerRunner) fetchAndWriteToken(ctx context.Context) error {
	return r.fetchAndWriteTokenWithRetry(ctx, defaultRetryPolicy)
}

// ctx must be a cancellable context.
// retry specifies the refresher goroutine's retry policy.
func (r *ContainerRunner) fetchAndWriteTokenWithRetry(ctx context.Context,
	retry func() *backoff.ExponentialBackOff) error {
	if err := os.MkdirAll(launcherfile.HostTmpPath, 0755); err != nil {
		return err
	}
	duration, err := r.refreshToken(ctx)
	if err != nil {
		return err
	}

	// Set a timer to refresh the token before it expires.
	timer := time.NewTimer(duration)
	go func() {
		for {
			select {
			case <-ctx.Done():
				timer.Stop()
				r.logger.Info("token refreshing stopped")
				return
			case <-timer.C:
				r.logger.Info("refreshing attestation verifier OIDC token")
				var duration time.Duration
				// Refresh token with default retry policy.
				err := backoff.RetryNotify(
					func() error {
						duration, err = r.refreshToken(ctx)
						return err
					},
					retry(),
					func(err error, t time.Duration) {
						r.logger.Error(fmt.Sprintf("failed to refresh attestation service token at time %v: %v", t, err))
					})
				if err != nil {
					r.logger.Error(fmt.Sprintf("failed all attempts to refresh attestation service token, stopping refresher: %v", err))
					return
				}

				timer.Reset(duration)
			}
		}
	}()

	return nil
}

// getNextRefreshFromExpiration returns the Duration for the next run of the
// token refresher goroutine. It expects pre-validation that expiration is in
// the future (e.g., time.Now < expiration).
func getNextRefreshFromExpiration(expiration time.Duration, random float64) time.Duration {
	diff := defaultRefreshJitter * float64(expiration)
	center := defaultRefreshMultiplier * float64(expiration)
	minRange := center - diff
	return time.Duration(minRange + random*2*diff)
}

/*
defaultRetryPolicy retries as follows:

Given the following arguments, the retry sequence will be:

	RetryInterval = 60 sec
	RandomizationFactor = 0.5
	Multiplier = 2
	MaxInterval = 3600 sec
	MaxElapsedTime = 0 (never stops retrying)

	Request #  RetryInterval (seconds)  Randomized Interval (seconds)
									 RetryInterval*[1-RandFactor, 1+RandFactor]
	 1          60                      [30,   90]
	 2          120                     [60,   180]
	 3          240                     [120,  360]
	 4          480                     [240,  720]
	 5          960                     [480,  1440]
	 6          1920                    [960,  2880]
	 7          3600 (MaxInterval)      [1800,  5400]
	 8          3600 (MaxInterval)      [1800,  5400]
	 ...
*/
func defaultRetryPolicy() *backoff.ExponentialBackOff {
	expBack := backoff.NewExponentialBackOff()
	expBack.InitialInterval = time.Minute
	expBack.RandomizationFactor = 0.5
	expBack.Multiplier = 2
	expBack.MaxInterval = time.Hour
	// Never stop retrying.
	expBack.MaxElapsedTime = 0
	return expBack
}

func pullImageBackoffPolicy() backoff.BackOff {
	b := backoff.NewConstantBackOff(time.Millisecond * 500)
	return backoff.WithMaxRetries(b, 3)
}

// Run the container
// Container output will always be redirected to logger writer for now
func (r *ContainerRunner) Run(ctx context.Context) error {
	// Note start time for workload setup.
	start := time.Now()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := r.measureCELEvents(ctx); err != nil {
		return fmt.Errorf("failed to measure CEL events: %v", err)
	}

	// Only refresh token if agent has a default GCA client (not ITA use case)
	// AND GcaRefresh is not disabled
	if r.launchSpec.ITAConfig.ITARegion == "" && !r.launchSpec.DisableGcaRefresh {
		if err := r.fetchAndWriteToken(ctx); err != nil {
			return fmt.Errorf("failed to fetch and write OIDC token: %v", err)
		}
	}

	// create and start the TEE server
	r.logger.Info("EnableOnDemandAttestation is enabled: initializing TEE server.")

	attestClients := teeserver.AttestClients{}

	if r.launchSpec.FakeVerifierEnabled {
		fakeClient := fake.NewClient(nil)
		attestClients.GCA = fakeClient
		attestClients.ITA = fakeClient
	} else if r.launchSpec.ITAConfig.ITARegion != "" {
		itaClient, err := ita.NewClient(r.launchSpec.ITAConfig)
		if err != nil {
			return fmt.Errorf("failed to create ITA client: %v", err)
		}

		attestClients.ITA = itaClient
	} else {
		gcaClient, err := util.NewRESTClient(ctx, r.launchSpec.GcaAddress, r.launchSpec.ProjectID, r.launchSpec.Region)
		if err != nil {
			if !r.launchSpec.DisableGcaRefresh {
				return fmt.Errorf("failed to create REST verifier client: %v", err)
			}
			// If GCA refresh is disabled, swallow the error and continue.
			r.logger.Info("Failed to create the GCA client, but GCA refresh is disabled so the launch will continue: %v", err)
			gcaClient = nil
		}
		attestClients.GCA = gcaClient
	}

	var workloadService *workloadservice.Server
	// create and start the key manager server
	if r.launchSpec.Experiments.EnableKeyManager {
		r.logger.Info("EnableKeyManager experiment is enabled: initializing KeyManager server.")
		keyManagerServer, err := workloadservice.New(ctx, path.Join(launcherfile.HostTmpPath, keyManagerSocket), keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM_EMULATED)
		if err != nil {
			return fmt.Errorf("failed to create the KeyManager server: %v", err)
		}
		workloadService = keyManagerServer
		go keyManagerServer.Serve()
		defer keyManagerServer.Shutdown(ctx)
	}

	teeServer, err := teeserver.New(ctx, path.Join(launcherfile.HostTmpPath, teeServerSocket), r.attestAgent, r.logger, r.launchSpec, attestClients, workloadService)
	if err != nil {
		return fmt.Errorf("failed to create the TEE server: %v", err)
	}
	go teeServer.Serve()
	defer teeServer.Shutdown(ctx)

	// Avoids breaking existing memory monitoring tests that depend on this log.
	if r.launchSpec.MonitoringEnabled == spec.None {
		r.logger.Info("MemoryMonitoring is disabled by the VM operator")
	}

	var streamOpt cio.Opt
	switch r.launchSpec.LogRedirect {
	case spec.Nowhere:
		streamOpt = cio.WithStreams(nil, nil, nil)
		r.logger.Info("Container stdout/stderr will not be redirected.")
	case spec.Everywhere:
		w := io.MultiWriter(os.Stdout, r.serialConsole)
		streamOpt = cio.WithStreams(nil, w, w)
		r.logger.Info("Container stdout/stderr will be redirected to serial and Cloud Logging. This may result in performance issues due to slow serial console writes.")
	case spec.CloudLogging:
		streamOpt = cio.WithStreams(nil, os.Stdout, os.Stdout)
		r.logger.Info("Container stdout/stderr will be redirected to Cloud Logging.")
	case spec.Serial:
		streamOpt = cio.WithStreams(nil, r.serialConsole, r.serialConsole)
		r.logger.Info("Container stdout/stderr will be redirected to serial logging. This may result in performance issues due to slow serial console writes.")
	default:
		return fmt.Errorf("unknown logging redirect location: %v", r.launchSpec.LogRedirect)
	}

	tasks := make([]containerd.Task, len(r.container))
	var mainTask containerd.Task
	var mainExitStatusC <- chan containerd.ExitStatus

	for i, c := range r.container {
		task, err := c.NewTask(ctx, cio.NewCreator(streamOpt))
		if err != nil {
			return &RetryableError{err}
		}

		//Only the main task is deferred here, Sidecar tasks handle their own deletion. 
		if r.launchSpec.Containers[i].ContainerType == spec.MainContainer {
			defer task.Delete(ctx)
			mainTask = task
		}
		tasks[i] = task
	}

	r.enableGracefulShutdown(ctx, tasks)

	setupDuration := time.Since(start)
	r.logger.Info("Workload setup completed",
		"setup_sec", setupDuration.Seconds(),
	)

	//Wait and Start all tasks
	start = time.Now()
	r.logger.Info("workload task started")
	for i, task := range tasks {
		exitStatusC, err := task.Wait(ctx)
		if err != nil {
			r.logger.Error(err.Error())
		}

		if task == mainTask {
			mainExitStatusC = exitStatusC
		} else {
			// For sidecars, spawn a monitor to handle restarts in the background
			go r.monitorSidecar(ctx, r.container[i], r.launchSpec.Containers[i], streamOpt, task, exitStatusC)
		}

		if err := task.Start(ctx); err != nil {
			return &RetryableError{err}
		}
	}

	r.logger.Info("All workload tasks started")

	if mainTask != nil {
		status := <-mainExitStatusC
		workloadDuration := time.Since(start)
	
		code, _, err := status.Result()
		if err != nil {
			return err
		}
	
		if code != 0 {
			r.logger.Error("workload task ended and returned non-zero",
				"workload_execution_sec", workloadDuration.Seconds(),
			)
			return &WorkloadError{code}
		}
		r.logger.Info("workload task ended and returned 0",
			"workload_execution_sec", workloadDuration.Seconds(),
		)
	}
	return nil
}

func (r *ContainerRunner) enableGracefulShutdown(ctx context.Context, tasks []containerd.Task) {
	// In a hardened image, the launcher monitors the power button to signal a shutdown.
	if r.launchSpec.Hardened {
		// May be nil if listener initialization failed, which is not critical and is logged at that time.
		if r.powerButton != nil {
			go func() {
				err := r.powerButton.waitForShutdown()
				// Upon an error, we do not send SIGTERM to the task.
				if err != nil {
					if !errors.Is(err, os.ErrClosed) {
						r.logger.Error(err.Error())
					}
					return
				}
				for _, task := range tasks {
					if err = task.Kill(ctx, syscall.SIGTERM); err != nil {
						r.logger.Error(err.Error())
					}
				}
			}()
		}
		return
	}

	// In a debug image, the launcher relays SIGTERM from logind to the container.
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM)
		defer signal.Stop(sig)

		select {
		case <-ctx.Done():
			return
		case s := <-sig:
			r.logger.Info("received a signal", "sig", s)
			for _,task := range tasks {
				if err := task.Kill(ctx, syscall.SIGTERM); err != nil {
					r.logger.Error(err.Error())
				}
			}
		}
	}()
}

func pullImageWithRetries(f func() (containerd.Image, error), retry func() backoff.BackOff) (containerd.Image, error) {
	var err error
	var image containerd.Image
	err = backoff.Retry(func() error {
		image, err = f()
		return err
	}, retry())
	if err != nil {
		return nil, fmt.Errorf("failed to pull image with retries, the last error is: %w", err)
	}
	return image, nil
}

func pullImages(ctx context.Context, cdClient *containerd.Client, launchSpec spec.LaunchSpec, token oauth2.Token) ([]containerd.Image, error) {
	images := make([]containerd.Image, len(launchSpec.Containers))
	g, ctx := errgroup.WithContext(ctx)

	for i, cSpec := range launchSpec.Containers {
		i, cSpec := i, cSpec

		g.Go(func() error{
			var img containerd.Image
			var err error

			if token.Valid() {
				remoteOpt := containerd.WithResolver(registryauth.Resolver(token.AccessToken))
				img, err = pullImageWithRetries(
					func() (containerd.Image, error) {
						return cdClient.Pull(ctx, cSpec.ImageRef, containerd.WithPullUnpack, remoteOpt)
					},
					pullImageBackoffPolicy,
				)
				if err != nil {
					return fmt.Errorf("cannot pull the image for container %q: %w", cSpec.Name, err)
				}
			} else {
				img, err = pullImageWithRetries(
					func() (containerd.Image, error) {
						return cdClient.Pull(ctx, cSpec.ImageRef, containerd.WithPullUnpack)
					},
					pullImageBackoffPolicy,
				)
				if err != nil {
					return fmt.Errorf("cannot pull the image for container %q (no token, only works for a public image): %w", cSpec.Name, err)
				}
			}

			images[i] = img
			return nil
		})
	}
	
	err := g.Wait()
	if err != nil {
		return nil, err
	}
	return images, nil
}

// setupFirewall inspects explicit YAML ports first, falling back to OCI annotations only if explicit ports are absent and len == 1.
func setupFirewall(cSpec spec.ContainerSpec, imageConfig v1.ImageConfig) error {
	portsToOpen := make(map[string]struct{})

	if len(cSpec.Ports) > 0 {
		for _, p := range cSpec.Ports {
			protocol := p.Protocol
			if protocol == "" {
				protocol = "tcp"
			}
			key := fmt.Sprintf("%d/%s", p.ContainerPort, strings.ToLower(protocol))
			portsToOpen[key] = struct{}{}
		}
	} else if len(imageConfig.ExposedPorts) == 1 {
		portsToOpen = imageConfig.ExposedPorts
	}

	if len(portsToOpen) > 0 {
		return openPorts(portsToOpen)
	}
	return nil
}

// openPorts writes firewall rules to accept all traffic into that port and protocol using iptables.
func openPorts(ports map[string]struct{}) error {
	for k := range ports {
		portAndProtocol := strings.Split(k, "/")
		if len(portAndProtocol) != 2 {
			return fmt.Errorf("failed to parse port and protocol: got %s, expected [port]/[protocol] 80/tcp", portAndProtocol)
		}

		port := portAndProtocol[0]
		_, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return fmt.Errorf("received invalid port number: %v, %w", port, err)
		}

		protocol := portAndProtocol[1]
		if protocol != "tcp" && protocol != "udp" {
			return fmt.Errorf("received unknown protocol: got %s, expected tcp or udp", protocol)
		}

		// These 2 commands will write firewall rules to accept all INPUT packets for the given port/protocol
		// for IPv4 and IPv6 traffic.
		cmd := exec.Command("iptables", "-A", "INPUT", "-p", protocol, "--dport", port, "-j", "ACCEPT")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to open port on IPv4 %s %s: %v %s", port, protocol, err, out)
		}
		v6cmd := exec.Command("ip6tables", "-A", "INPUT", "-p", protocol, "--dport", port, "-j", "ACCEPT")
		out, err = v6cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to open port on IPv6 %s %s: %v %s", port, protocol, err, out)
		}
	}

	return nil
}

func getImageConfig(ctx context.Context, image containerd.Image) (v1.ImageConfig, error) {
	ic, err := image.Config(ctx)
	if err != nil {
		return v1.ImageConfig{}, err
	}
	switch ic.MediaType {
	case v1.MediaTypeImageConfig, images.MediaTypeDockerSchema2Config:
		p, err := content.ReadBlob(ctx, image.ContentStore(), ic)
		if err != nil {
			return v1.ImageConfig{}, err
		}
		var ociimage v1.Image
		if err := json.Unmarshal(p, &ociimage); err != nil {
			return v1.ImageConfig{}, err
		}
		return ociimage.Config, nil
	}
	return v1.ImageConfig{}, fmt.Errorf("unknown image config media type %s", ic.MediaType)
}

// Close cleans up the container and closes the connection to the contanerd daemon.
func (r *ContainerRunner) Close(ctx context.Context) {

	if r.powerButton != nil {
		if err := r.powerButton.Close(); err != nil {
			r.logger.Error("failed to close power button listener", "err", err.Error())
		}
	}
	
	//close the agent
	if r.attestAgent != nil {
		r.attestAgent.Close()
	}

	// Exit gracefully:
	// Delete container and close connection to attestation service.
	for _,c := range r.container {
		if c != nil {
			if err := c.Delete(ctx, containerd.WithSnapshotCleanup); err != nil {
				r.logger.Error("failed to delete container", "err", err.Error())
			}
		}
	}	
}

// withRlimits sets the rlimit (like the max file descriptor) for the container process
func withRlimits(rlimits []specs.POSIXRlimit) oci.SpecOpts {
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
		s.Process.Rlimits = rlimits
		return nil
	}
}

// Set the container process's OOM score.
func withOOMScoreAdj(oomScore int) oci.SpecOpts {
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
		s.Process.OOMScoreAdj = &oomScore
		return nil
	}
}

// appendCgroupRw mount maps a cgroup as read-write.
func appendCgroupRw(mounts []specs.Mount) []specs.Mount {
	m := specs.Mount{
		Destination: "/sys/fs/cgroup",
		Type:        "cgroup",
		Source:      "cgroup",
		Options:     []string{"rw", "nosuid", "noexec", "nodev"},
	}

	return append(mounts, m)
}

type multiImageSignatureFetcher struct {
	images 		[]containerd.Image
	cdClient 	*containerd.Client
	mdsClient *metadata.Client
}

func (m *multiImageSignatureFetcher) FetchImageSignatures(ctx context.Context, targetRepository string) ([]ociverifier.Signature, error) {
	for _, img := range m.images {
		if img.Name() == targetRepository || strings.HasPrefix(img.Name(), targetRepository+":") || strings.HasPrefix(img.Name(), targetRepository+"@") {
			sdClient := getSignatureDiscoveryClient(m.cdClient, m.mdsClient, img.Target())
			return sdClient.FetchImageSignatures(ctx, targetRepository)
		}
	}
	return nil, fmt.Errorf("no matching image found for repository %q", targetRepository)
}

// monitorSidecar handles the restart policy loop for sidecar containers
func (r *ContainerRunner) monitorSidecar(ctx context.Context, c containerd.Container, cSpec spec.ContainerSpec, streamOpt cio.Opt, initialTask containerd.Task, initialExitStatusC <-chan containerd.ExitStatus) {
	task := initialTask
	exitStatusC := initialExitStatusC

	//Ensure the last task instance is cleaned up when the monitor exits
	defer func() {
		if task != nil {
			task.Delete(ctx)
		}
	}()

	for {
		status := <-exitStatusC
		code, _, _ := status.Result()

		//Clean up the exited task before recreating
		task.Delete(ctx)
		
		shouldRestart := false
		if cSpec.RestartPolicy == spec.Always {
			shouldRestart = true
		} else if cSpec.RestartPolicy == spec.OnFailure && code != 0 {
			shouldRestart = true
		}

		if shouldRestart {
			r.logger.Info("restarting sidecar container", "container", cSpec.Name)
			newTask, err := c.NewTask(ctx, cio.NewCreator(streamOpt))
			if err != nil {
				// If ctx is cancelled (main exited), this will safely fail and the monitor
				r.logger.Error("Failed to create new task for sidecar", "container", cSpec.Name, "err", err.Error())
				return
			}
			task = newTask
	
			exitStatusC, err = task.Wait(ctx)
			if err != nil {
				r.logger.Error("Failed to wait on new task for sidecar", "container", cSpec.Name, "err", err.Error())
				return
			}
	
			if err := task.Start(ctx); err != nil {
				r.logger.Error("Failed to start new task for sidecar", "container", cSpec.Name, "err", err.Error())
				return
			}
		} else {
			r.logger.Info("Sidecar container exited, not restarting", "container", cSpec.Name, "code", code)
			break
		}
	}
}