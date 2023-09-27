// Package launcher contains functionalities to start a measured workload
package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/compute/metadata"
	"github.com/cenkalti/backoff/v4"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/oci"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/go-tpm-tools/cel"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/launcher/agent"
	"github.com/google/go-tpm-tools/launcher/internal/signaturediscovery"
	"github.com/google/go-tpm-tools/launcher/launcherfile"
	"github.com/google/go-tpm-tools/launcher/spec"
	"github.com/google/go-tpm-tools/launcher/verifier"
	"github.com/google/go-tpm-tools/launcher/verifier/rest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
)

// ContainerRunner contains information about the container settings
type ContainerRunner struct {
	container     containerd.Container
	launchSpec    spec.LaunchSpec
	attestAgent   agent.AttestationAgent
	logger        *log.Logger
	serialConsole *os.File
}

const tokenFileTmp = ".token.tmp"

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

func fetchImpersonatedToken(ctx context.Context, serviceAccount string, audience string, opts ...option.ClientOption) ([]byte, error) {
	config := impersonate.IDTokenConfig{
		Audience:        audience,
		TargetPrincipal: serviceAccount,
		IncludeEmail:    true,
	}

	tokenSource, err := impersonate.IDTokenSource(ctx, config, opts...)
	if err != nil {
		return nil, fmt.Errorf("error creating token source: %v", err)
	}

	token, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("error retrieving token: %v", err)
	}

	return []byte(token.AccessToken), nil
}

// NewRunner returns a runner.
func NewRunner(ctx context.Context, cdClient *containerd.Client, token oauth2.Token, launchSpec spec.LaunchSpec, mdsClient *metadata.Client, tpm io.ReadWriteCloser, logger *log.Logger, serialConsole *os.File) (*ContainerRunner, error) {
	image, err := initImage(ctx, cdClient, launchSpec, token)
	if err != nil {
		return nil, err
	}

	mounts := make([]specs.Mount, 0)
	mounts = appendTokenMounts(mounts)
	envs, err := formatEnvVars(launchSpec.Envs)
	if err != nil {
		return nil, err
	}
	// Check if there is already a container
	container, err := cdClient.LoadContainer(ctx, containerID)
	if err == nil {
		// container exists, delete it first
		container.Delete(ctx, containerd.WithSnapshotCleanup)
	}

	logger.Printf("Operator Input Image Ref   : %v\n", image.Name())
	logger.Printf("Image Digest               : %v\n", image.Target().Digest)
	logger.Printf("Operator Override Env Vars : %v\n", envs)
	logger.Printf("Operator Override Cmd      : %v\n", launchSpec.Cmd)

	imageConfig, err := getImageConfig(ctx, image)
	if err != nil {
		return nil, err
	}

	logger.Printf("Exposed Ports:             : %v\n", imageConfig.ExposedPorts)
	if err := openPorts(imageConfig.ExposedPorts); err != nil {
		return nil, err
	}

	logger.Printf("Image Labels               : %v\n", imageConfig.Labels)
	launchPolicy, err := spec.GetLaunchPolicy(imageConfig.Labels)
	if err != nil {
		return nil, err
	}
	if err := launchPolicy.Verify(launchSpec); err != nil {
		return nil, err
	}

	if imageConfigDescriptor, err := image.Config(ctx); err != nil {
		logger.Println(err)
	} else {
		logger.Printf("Image ID                   : %v\n", imageConfigDescriptor.Digest)
		logger.Printf("Image Annotations          : %v\n", imageConfigDescriptor.Annotations)
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

	container, err = cdClient.NewContainer(
		ctx,
		containerID,
		containerd.WithImage(image),
		containerd.WithNewSnapshot(snapshotID, image),
		containerd.WithNewSpec(
			oci.WithImageConfigArgs(image, launchSpec.Cmd),
			oci.WithEnv(envs),
			oci.WithMounts(mounts),
			// following 4 options are here to allow the container to have
			// the host network (same effect as --net-host in ctr command)
			oci.WithHostHostsFile,
			oci.WithHostResolvconf,
			oci.WithHostNamespace(specs.NetworkNamespace),
			oci.WithEnv([]string{fmt.Sprintf("HOSTNAME=%s", hostname)}),
			withRlimits(rlimits),
		),
	)
	if err != nil {
		if container != nil {
			container.Delete(ctx, containerd.WithSnapshotCleanup)
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

	// Fetch ID token with specific audience.
	// See https://cloud.google.com/functions/docs/securing/authenticating#functions-bearer-token-example-go.
	principalFetcher := func(audience string) ([][]byte, error) {
		u := url.URL{
			Path: "instance/service-accounts/default/identity",
			RawQuery: url.Values{
				"audience": {audience},
				"format":   {"full"},
			}.Encode(),
		}
		idToken, err := mdsClient.Get(u.String())
		if err != nil {
			return nil, fmt.Errorf("failed to get principal tokens: %w", err)
		}

		tokens := [][]byte{[]byte(idToken)}

		// Fetch impersonated ID tokens.
		for _, sa := range launchSpec.ImpersonateServiceAccounts {
			idToken, err := fetchImpersonatedToken(ctx, sa, audience)
			if err != nil {
				return nil, fmt.Errorf("failed to get impersonated token for %v: %w", sa, err)
			}

			tokens = append(tokens, idToken)
		}
		return tokens, nil
	}

	asAddr := launchSpec.AttestationServiceAddr

	verifierClient, err := getRESTClient(ctx, asAddr, launchSpec)
	if err != nil {
		return nil, fmt.Errorf("failed to create REST verifier client: %v", err)
	}

	// Create a new signaturediscovery cleint to fetch signatures.
	sdClient := getSignatureDiscoveryClient(cdClient, token, image.Target())
	return &ContainerRunner{
		container,
		launchSpec,
		agent.CreateAttestationAgent(tpm, client.GceAttestationKeyECC, verifierClient, principalFetcher, sdClient, launchSpec, logger),
		logger,
		serialConsole,
	}, nil
}

func getSignatureDiscoveryClient(cdClient *containerd.Client, token oauth2.Token, imageDesc v1.Descriptor) signaturediscovery.Fetcher {
	var remoteOpt containerd.RemoteOpt
	if token.Valid() {
		remoteOpt = containerd.WithResolver(Resolver(token.AccessToken))
	}
	return signaturediscovery.New(cdClient, imageDesc, remoteOpt)
}

// getRESTClient returns a REST verifier.Client that points to the given address.
// It defaults to the Attestation Verifier instance at
// https://confidentialcomputing.googleapis.com.
func getRESTClient(ctx context.Context, asAddr string, spec spec.LaunchSpec) (verifier.Client, error) {
	httpClient, err := google.DefaultClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %v", err)
	}

	opts := []option.ClientOption{option.WithHTTPClient(httpClient)}
	if asAddr != "" {
		opts = append(opts, option.WithEndpoint(asAddr))
	}

	restClient, err := rest.NewClient(ctx, spec.ProjectID, spec.Region, opts...)
	if err != nil {
		return nil, err
	}
	return restClient, nil
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

	separator := cel.CosTlv{
		EventType:    cel.LaunchSeparatorType,
		EventContent: nil, // Success
	}
	return r.attestAgent.MeasureEvent(separator)
}

// Retrieves an OIDC token from the attestation service, and returns how long
// to wait before attemping to refresh it.
// The token file will be written to a tmp file and then renamed.
func (r *ContainerRunner) refreshToken(ctx context.Context) (time.Duration, error) {
	r.logger.Print("refreshing attestation verifier OIDC token")
	token, err := r.attestAgent.Attest(ctx)
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
	claimsString, err := json.MarshalIndent(mapClaims, "", "  ")
	if err != nil {
		return 0, fmt.Errorf("failed to format claims: %w", err)
	}
	r.logger.Println(string(claimsString))

	return getNextRefreshFromExpiration(time.Until(claims.ExpiresAt.Time), rand.Float64()), nil
}

// ctx must be a cancellable context.
func (r *ContainerRunner) fetchAndWriteToken(ctx context.Context) error {
	return r.fetchAndWriteTokenWithRetry(ctx, defaultRetryPolicy())
}

// ctx must be a cancellable context.
// retry specifies the refresher goroutine's retry policy.
func (r *ContainerRunner) fetchAndWriteTokenWithRetry(ctx context.Context,
	retry *backoff.ExponentialBackOff) error {
	if err := os.MkdirAll(launcherfile.HostTmpPath, 0744); err != nil {
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
				r.logger.Println("token refreshing stopped")
				return
			case <-timer.C:
				var duration time.Duration
				// Refresh token with default retry policy.
				err := backoff.RetryNotify(
					func() error {
						duration, err = r.refreshToken(ctx)
						return err
					},
					retry,
					func(err error, t time.Duration) {
						r.logger.Printf("failed to refresh attestation service token at time %v: %v", t, err)
					})
				if err != nil {
					r.logger.Printf("failed all attempts to refresh attestation service token, stopping refresher: %v", err)
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
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := r.measureContainerClaims(ctx); err != nil {
		return fmt.Errorf("failed to measure container claims: %v", err)
	}
	if err := r.fetchAndWriteToken(ctx); err != nil {
		return fmt.Errorf("failed to fetch and write OIDC token: %v", err)
	}

	r.logger.Printf("EnableTestFeatureForImage is set to %v\n", r.launchSpec.Experiments.EnableTestFeatureForImage)

	var streamOpt cio.Opt
	switch r.launchSpec.LogRedirect {
	case spec.Nowhere:
		streamOpt = cio.WithStreams(nil, nil, nil)
		r.logger.Println("Container stdout/stderr will not be redirected.")
	case spec.Everywhere:
		w := io.MultiWriter(os.Stdout, r.serialConsole)
		streamOpt = cio.WithStreams(nil, w, w)
		r.logger.Println("Container stdout/stderr will be redirected to serial and Cloud Logging. " +
			"This may result in performance issues due to slow serial console writes.")
	case spec.CloudLogging:
		streamOpt = cio.WithStreams(nil, os.Stdout, os.Stdout)
		r.logger.Println("Container stdout/stderr will be redirected to Cloud Logging.")
	case spec.Serial:
		streamOpt = cio.WithStreams(nil, r.serialConsole, r.serialConsole)
		r.logger.Println("Container stdout/stderr will be redirected to serial logging. " +
			"This may result in performance issues due to slow serial console writes.")
	default:
		return fmt.Errorf("unknown logging redirect location: %v", r.launchSpec.LogRedirect)
	}

	task, err := r.container.NewTask(ctx, cio.NewCreator(streamOpt))
	if err != nil {
		return &RetryableError{err}
	}
	defer task.Delete(ctx)

	exitStatusC, err := task.Wait(ctx)
	if err != nil {
		r.logger.Println(err)
	}
	r.logger.Println("workload task started")

	if err := task.Start(ctx); err != nil {
		return &RetryableError{err}
	}
	status := <-exitStatusC

	code, _, err := status.Result()
	if err != nil {
		return err
	}

	if code != 0 {
		r.logger.Println("workload task ended and returned non-zero")
		return &WorkloadError{code}
	}
	r.logger.Println("workload task ended and returned 0")
	return nil
}

func initImage(ctx context.Context, cdClient *containerd.Client, launchSpec spec.LaunchSpec, token oauth2.Token) (containerd.Image, error) {
	if token.Valid() {
		remoteOpt := containerd.WithResolver(Resolver(token.AccessToken))

		image, err := cdClient.Pull(ctx, launchSpec.ImageRef, containerd.WithPullUnpack, remoteOpt)
		if err != nil {
			return nil, fmt.Errorf("cannot pull the image: %w", err)
		}
		return image, nil
	}
	image, err := cdClient.Pull(ctx, launchSpec.ImageRef, containerd.WithPullUnpack)
	if err != nil {
		return nil, fmt.Errorf("cannot pull the image (no token, only works for a public image): %w", err)
	}
	return image, nil
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

		// This command will write a firewall rule to accept all INPUT packets for the given port/protocol.
		cmd := exec.Command("iptables", "-A", "INPUT", "-p", protocol, "--dport", port, "-j", "ACCEPT")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to open port %s %s: %v %s", port, protocol, err, out)
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
	// Exit gracefully:
	// Delete container and close connection to attestation service.
	r.container.Delete(ctx, containerd.WithSnapshotCleanup)
}

// withRlimits sets the rlimit (like the max file descriptor) for the container process
func withRlimits(rlimits []specs.POSIXRlimit) oci.SpecOpts {
	return func(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
		s.Process.Rlimits = rlimits
		return nil
	}
}
