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
	"net/http"
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
	gocni "github.com/containerd/go-cni"

	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/oci"
	"github.com/containerd/containerd/remotes"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/go-tpm-tools/agent"
	"github.com/google/go-tpm-tools/cel"
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
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/protobuf/proto"
)

// ContainerRunner contains information about the container settings
type ContainerRunner struct {
	container      containerd.Container
	launchSpec     spec.LaunchSpec
	launchPolicy   spec.LaunchPolicy
	attestAgent    agent.AttestationAgent
	logger         logging.Logger
	workloadLogger logging.Logger
	gpuAttester    gpu.Attester
	serialConsole  *os.File
	powerButton    *powerButtonListener // Populated only for a hardened image
	attestClients  teeserver.AttestClients
	cni            gocni.CNI
}

const tokenFileTmp = ".token.tmp"

const teeServerSocket = "teeserver.sock"
const keyManagerSocket = "kmaserver.sock"
const keyManagerGrpcSocket = "kmaserver-grpc.sock"

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

// Constants for a non-root container.
const (
	hostUIDBegin = 100000 // Starting (outside container) uid for the root user inside the container
	hostGIDBegin = 100000 // Starting (outside container) gid for the root group inside the container
	userNSSize   = 65536  // 16-bit range of uid/gid inside the container

	cniConfigDir = "/etc/cni/net.d"
	cniBinDir    = "/opt/cni/bin"
	netnsPathFmt = "/proc/%d/ns/net"
)

// ContainerdClient abstracts the subset of containerd.Client methods used by the
// runner. This enables unit testing by allowing a mock client to be injected.
type ContainerdClient interface {
	LoadContainer(ctx context.Context, id string) (containerd.Container, error)
	NewContainer(ctx context.Context, id string, opts ...containerd.NewContainerOpts) (containerd.Container, error)
	Pull(ctx context.Context, ref string, opts ...containerd.RemoteOpt) (containerd.Image, error)
}

// RunnerConfig contains the configuration for creating a ContainerRunner.
type RunnerConfig struct {
	ContainerdClient ContainerdClient
	Image            containerd.Image
	AttestAgent      agent.AttestationAgent
	GpuAttester      gpu.Attester
	AttestClients    teeserver.AttestClients
	LaunchSpec       spec.LaunchSpec
	Logger           logging.Logger
	WorkloadLogger   logging.Logger
	SerialConsole    *os.File
}

// NewRunner returns a runner.
func NewRunner(ctx context.Context, cfg *RunnerConfig) (*ContainerRunner, error) {
	cdClient := cfg.ContainerdClient
	launchSpec := cfg.LaunchSpec
	logger := cfg.Logger
	workloadLogger := cfg.WorkloadLogger
	serialConsole := cfg.SerialConsole
	image := cfg.Image
	attestAgent := cfg.AttestAgent

	envs, err := formatEnvVars(launchSpec.Envs)
	if err != nil {
		return nil, err
	}
	// Check if there is already a container
	container, err := cdClient.LoadContainer(ctx, containerID)
	if err == nil {
		// container exists, delete it first
		// TODO: consider handling or logging cleanup error.
		_ = container.Delete(ctx, containerd.WithSnapshotCleanup)
	}

	var loggedEnvs []string
	for _, env := range envs {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			loggedEnvs = append(loggedEnvs, parts[0]+"=[REDACTED]")
		} else {
			loggedEnvs = append(loggedEnvs, env)
		}
	}

	logger.Info("Preparing Container Runner",
		"operator_input_image_ref", image.Name(),
		"image_digest", image.Target().Digest,
		"operator_override_env_vars", loggedEnvs,
		"operator_override_cmd", launchSpec.Cmd,
	)

	imageConfig, err := getImageConfig(ctx, image)
	if err != nil {
		return nil, err
	}

	logger.Info(fmt.Sprintf("Exposed Ports:             : %v\n", imageConfig.ExposedPorts))
	logger.Info(fmt.Sprintf("Image Labels               : %v\n", imageConfig.Labels))
	launchPolicy, err := spec.GetLaunchPolicy(imageConfig.Labels, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image Launch Policy: %v: contact the image author", err)
	}
	if err := launchPolicy.Verify(launchSpec); err != nil {
		return nil, err
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

	logger.Info(fmt.Sprintf("Launch Policy              : %+v\n", launchPolicy))

	if imageConfigDescriptor, err := image.Config(ctx); err != nil {
		logger.Error(err.Error())
	} else {
		logger.Info("Retrieved image config",
			"image_id", imageConfigDescriptor.Digest,
			"image_annotations", imageConfigDescriptor.Annotations,
		)
	}

	hostname, err := os.Hostname()
	if err != nil {
		return nil, &RetryableError{fmt.Errorf("cannot get hostname: [%w]", err)}
	}

	rlimits := []specs.POSIXRlimit{{
		Type: "RLIMIT_NOFILE",
		Hard: nofile,
		Soft: nofile,
	}}

	specOpts := []oci.SpecOpts{
		oci.WithImageConfigArgs(image, launchSpec.Cmd),
		oci.WithEnv(envs),
		oci.WithMounts(mounts),
		// following 4 options are here to allow the container to have
		// the host network (same effect as --net-host in ctr command)
		oci.WithHostHostsFile,
		oci.WithHostResolvconf,
		oci.WithEnv([]string{fmt.Sprintf("HOSTNAME=%s", hostname)}),
		oci.WithAddedCapabilities(launchSpec.AddedCapabilities),
		withRlimits(rlimits),
		withOOMScoreAdj(defaultOOMScore),
	}

	// If we use non-root container, we enable both the user and network namespaces.
	// Otherwise, we use host network without enabling the namespaces.
	if launchPolicy.NonrootContainer {
		specOpts = append(specOpts,
			oci.WithUserNamespace(
				[]specs.LinuxIDMapping{{ContainerID: 0, HostID: hostUIDBegin, Size: userNSSize}},
				[]specs.LinuxIDMapping{{ContainerID: 0, HostID: hostGIDBegin, Size: userNSSize}},
			),
		)
	} else {
		specOpts = append(specOpts, oci.WithHostNamespace(specs.NetworkNamespace))
	}

	specOpts, err := createOCISpecOpts(image, launchSpec, envs, listFilesWithPrefix, logger)
	if err != nil {
		return nil, err
	}

	conOpts := []containerd.NewContainerOpts{containerd.WithImage(image)}
	if launchPolicy.NonrootContainer { // When a non-root container is used, we remap the snapshop with the non-root user.
		conOpts = append(conOpts, containerd.WithRemappedSnapshot(snapshotID, image, hostUIDBegin, hostGIDBegin))
	} else {
		conOpts = append(conOpts, containerd.WithNewSnapshot(snapshotID, image))
	}
	conOpts = append(conOpts, containerd.WithNewSpec(specOpts...))
	container, err = cdClient.NewContainer(ctx, containerID, conOpts...)
	if err != nil {
		if container != nil {
			// TODO: consider handling or logging cleanup error.
			_ = container.Delete(ctx, containerd.WithSnapshotCleanup)
		}
		return nil, &RetryableError{fmt.Errorf("failed to create a container: [%w]", err)}
	}

	containerSpec, err := container.Spec(ctx)
	if err != nil {
		return nil, &RetryableError{err}
	}

	// Container process Args length should be strictly longer than the Cmd
	// override length set by the operator, as we want the Entrypoint filed
	// to be mandatory for the image.
	// Roughly speaking, Args = Entrypoint + Cmd
	if len(containerSpec.Process.Args) <= len(launchSpec.Cmd) {
		return nil,
			fmt.Errorf("length of Args [%d] is shorter or equal to the length of the given Cmd [%d], maybe the Entrypoint is set to empty in the image?",
				len(containerSpec.Process.Args), len(launchSpec.Cmd))
	}

	var powerButton *powerButtonListener
	if launchSpec.Hardened {
		powerButton, err = newPowerButtonListener(logger)
		if err != nil {
			logger.Error(err.Error())
		}
	}

	var cni gocni.CNI
	if launchPolicy.NonrootContainer {
		if cni, err = newCNI(); err != nil {
			return nil, err
		}
	}

	return &ContainerRunner{
		container,
		launchSpec,
		launchPolicy,
		attestAgent,
		logger,
		workloadLogger,
		cfg.GpuAttester,
		serialConsole,
		powerButton,
		cfg.AttestClients,
		cni,
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

func getSignatureDiscoveryClient(cdClient ContainerdClient, mdsClient *metadata.Client, imageDesc v1.Descriptor, googleHTTPClient *http.Client) signaturediscovery.Fetcher {
	resolverFetcher := func(ctx context.Context) (remotes.Resolver, error) {
		return registryauth.RefreshResolver(ctx, mdsClient, googleHTTPClient)
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
	image, err := r.container.Image(ctx)
	if err != nil {
		return err
	}
	if err := r.attestAgent.MeasureEvent(cel.CosTlv{EventType: cel.ImageRefType, EventContent: []byte(image.Name())}); err != nil {
		return err
	}
	if err := r.attestAgent.MeasureEvent(cel.CosTlv{EventType: cel.ImageDigestType, EventContent: []byte(image.Target().Digest)}); err != nil {
		return err
	}
	if err := r.attestAgent.MeasureEvent(cel.CosTlv{EventType: cel.RestartPolicyType, EventContent: []byte(r.launchSpec.RestartPolicy)}); err != nil {
		return err
	}
	if imageConfigDescriptor, err := image.Config(ctx); err == nil { // if NO error
		if err := r.attestAgent.MeasureEvent(cel.CosTlv{EventType: cel.ImageIDType, EventContent: []byte(imageConfigDescriptor.Digest)}); err != nil {
			return err
		}
	}

	containerSpec, err := r.container.Spec(ctx)
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
	envs, err := formatEnvVars(r.launchSpec.Envs)
	if err != nil {
		return err
	}
	for _, env := range envs {
		if err := r.attestAgent.MeasureEvent(cel.CosTlv{EventType: cel.OverrideEnvType, EventContent: []byte(env)}); err != nil {
			return err
		}
	}
	for _, arg := range r.launchSpec.Cmd {
		if err := r.attestAgent.MeasureEvent(cel.CosTlv{EventType: cel.OverrideArgType, EventContent: []byte(arg)}); err != nil {
			return err
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

	var workloadService *workloadservice.Server
	// create and start the key manager server
	if r.launchSpec.Experiments.EnableKeyManager {
		r.logger.Info("EnableKeyManager experiment is enabled: initializing KeyManager server.")
		keyManagerSocketPath := path.Join(launcherfile.HostTmpPath, keyManagerSocket)
		keyManagerServer, err := workloadservice.New(ctx, keyManagerSocketPath, keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM_EMULATED)

		if err != nil {
			return fmt.Errorf("failed to create the KeyManager server: %v", err)
		}
		if err := verifySocketPermissions(keyManagerSocketPath); err != nil {
			return fmt.Errorf("failed to verify KeyManager socket permissions: %w", err)
		}
		workloadService = keyManagerServer
		go func() { _ = keyManagerServer.Serve() }()
		defer func() { _ = keyManagerServer.Shutdown(ctx) }()
	}

	teeServerSocketPath := path.Join(launcherfile.HostTmpPath, teeServerSocket)
	teeServer, err := teeserver.New(ctx, teeServerSocketPath, r.attestAgent, r.logger, r.launchSpec, r.attestClients, workloadService)
	if err != nil {
		return fmt.Errorf("failed to create the TEE server: %v", err)
	}
	if err := verifySocketPermissions(teeServerSocketPath); err != nil {
		return fmt.Errorf("failed to verify TEE server socket permissions: %w", err)
	}

	go func() { _ = teeServer.Serve() }()
	defer func() { _ = teeServer.Shutdown(ctx) }()

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
		stdoutWriter := logging.NewInfoWriter(r.workloadLogger)
		stderrWriter := logging.NewErrorWriter(r.workloadLogger)
		streamOpt = cio.WithStreams(nil, stdoutWriter, stderrWriter)
		r.logger.Info("Container stdout/stderr will be redirected to Cloud Logging with INFO and ERROR severities respectively.")
	case spec.Serial:
		streamOpt = cio.WithStreams(nil, r.serialConsole, r.serialConsole)
		r.logger.Info("Container stdout/stderr will be redirected to serial logging. This may result in performance issues due to slow serial console writes.")
	default:
		return fmt.Errorf("unknown logging redirect location: %v", r.launchSpec.LogRedirect)
	}

	var taskOpts []containerd.NewTaskOpts
	if r.launchPolicy.NonrootContainer {
		taskOpts = append(taskOpts, containerd.WithUIDOwner(hostUIDBegin), containerd.WithGIDOwner(hostGIDBegin))
	}

	task, err := r.container.NewTask(ctx, cio.NewCreator(streamOpt), taskOpts...)
	if err != nil {
		return &RetryableError{err}
	}
	defer task.Delete(ctx)
	defer func() {
		if task.IO() != nil {
			task.IO().Wait()
		}
	}()

	r.enableGracefulShutdown(ctx, task)

	// Opening ports.
	// Workload-requested ports are in the image config, and the container IP address can be obtained after the CNI setup.
	image, err := r.container.Image(ctx)
	if err != nil {
		return fmt.Errorf("failed to get image from container: %w", err)
	}
	imageConfig, err := getImageConfig(ctx, image)
	if err != nil {
		return fmt.Errorf("failed to get image config: %w", err)
	}
	var containerIP string
	if r.launchPolicy.NonrootContainer {
		containerIP, err = r.getContainerIP(ctx, fmt.Sprintf(netnsPathFmt, task.Pid()))
		if err != nil {
			return err
		}
	}
	if err := openPorts(imageConfig.ExposedPorts, containerIP); err != nil {
		return fmt.Errorf("failed to open and forward ports: %w", err)
	}

	setupDuration := time.Since(start)
	r.logger.Info("Workload setup completed",
		"setup_sec", setupDuration.Seconds(),
	)

	exitStatusC, err := task.Wait(ctx)
	if err != nil {
		r.logger.Error(err.Error())
	}

	// Update and verify socket permissions if in bc mode.
	if r.launchSpec.Experiments.BcMode {
		kmaServerSocketPath := path.Join(launcherfile.HostTmpPath, keyManagerSocket)
		kmaServerGrpcSocketPath := path.Join(launcherfile.HostTmpPath, keyManagerGrpcSocket)

		err := os.Chmod(kmaServerSocketPath, 0777)
		if err != nil {
			r.logger.Error("failed to chmod file %s: %v\n", kmaServerSocketPath, err)
		}
		err = os.Chmod(kmaServerGrpcSocketPath, 0777)
		if err != nil {
			r.logger.Error("failed to chmod file %s: %v\n", kmaServerGrpcSocketPath, err)
		}

		if err := verifySocketPermissions(kmaServerSocketPath); err != nil {
			r.logger.Error("failed to verify kmaserver socket permissions: %v", err)
		}
		if err := verifySocketPermissions(kmaServerGrpcSocketPath); err != nil {
			r.logger.Error("failed to verify kmaserver-grpc socket permissions: %v", err)
		}
	}

	// Start timer for workload execution.
	start = time.Now()
	r.logger.Info("workload task started")

	if err := task.Start(ctx); err != nil {
		return &RetryableError{err}
	}
	status := <-exitStatusC
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
	return nil
}

func (r *ContainerRunner) enableGracefulShutdown(ctx context.Context, task containerd.Task) {
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
				if err = task.Kill(ctx, syscall.SIGTERM); err != nil {
					r.logger.Error(err.Error())
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
			if err := task.Kill(ctx, syscall.SIGTERM); err != nil {
				r.logger.Error(err.Error())
			}
		}
	}()
}

// openPorts writes firewall rules to accept all traffic into that port and protocol using iptables.
// When `containerIP` is not empty, it implies that the namespace and CNI are used for the container.
// In that case, it also forwards traffic to the container via DNAT and allows container egress traffic.
func openPorts(ports map[string]struct{}, containerIP string) error {
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

		// Forward traffic from host port to container port with the same number.
		if containerIP != "" {
			forwardCmd := exec.Command("iptables", "-t", "nat", "-A", "PREROUTING",
				"-p", protocol, "--dport", port,
				"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%s", containerIP, port))

			out, err = forwardCmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("failed to forward port %s to container %s: %v %s", port, containerIP, err, out)
			}

			// Allow traffic in FORWARD chain to the container IP on this port
			forwardInCmd := exec.Command("iptables", "-A", "FORWARD", "-d", containerIP, "-p", protocol, "--dport", port, "-j", "ACCEPT")
			if out, err := forwardInCmd.CombinedOutput(); err != nil {
				return fmt.Errorf("failed to add FORWARD rule for container %s: %v %s", containerIP, err, out)
			}

		}
	}

	// Allow egress traffic from the container to go out
	if containerIP != "" {
		forwardOutCmd := exec.Command("iptables", "-A", "FORWARD", "-s", containerIP, "-j", "ACCEPT")
		if out, err := forwardOutCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to add FORWARD reply rule for container %s: %v %s", containerIP, err, out)
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

// Close the container runner
func (r *ContainerRunner) Close(ctx context.Context) {
	if r.powerButton != nil {
		if err := r.powerButton.Close(); err != nil {
			r.logger.Error("failed to close power button listener", "err", err.Error())
		}
	}

	// close the agent
	r.attestAgent.Close()

	// Cleanup network using go-cni
	if r.cni != nil {
		task, err := r.container.Task(ctx, nil)
		if err == nil {
			if err := r.cni.Remove(ctx, containerID, fmt.Sprintf(netnsPathFmt, task.Pid())); err != nil {
				r.logger.Error("failed to cleanup network via CNI", "error", err)
			}
		}
	}

	// Exit gracefully:
	// Delete container and close connection to attestation service.
	// TODO: consider handling or logging cleanup error.
	_ = r.container.Delete(ctx, containerd.WithSnapshotCleanup)
}

func newCNI() (gocni.CNI, error) {
	cni, err := gocni.New(
		gocni.WithPluginConfDir(cniConfigDir),
		gocni.WithPluginDir([]string{cniBinDir}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize CNI: %w", err)
	}
	if err := cni.Load(gocni.WithDefaultConf); err != nil {
		return nil, fmt.Errorf("failed to load CNI configurations: %w", err)
	}
	return cni, nil
}

func (r *ContainerRunner) getContainerIP(ctx context.Context, netnsPath string) (string, error) {
	if r.cni == nil {
		return "", fmt.Errorf("CNI is not initialized")
	}
	cniResult, err := r.cni.Setup(ctx, containerID, netnsPath)
	if err != nil {
		return "", fmt.Errorf("failed to setup network via CNI: %w", err)
	}
	r.logger.Info(fmt.Sprintf("CNI network setup completed: %v", cniResult))

	rawResults := cniResult.Raw()
	if len(rawResults) == 0 || len(rawResults[0].IPs) == 0 {
		return "", fmt.Errorf("failed to get container IP address")
	}
	// Currently, we have only single network interface defined with a single IP address by `10-workload.conf`.
	return rawResults[0].IPs[0].Address.IP.String(), nil
}
