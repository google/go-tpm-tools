package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path"
	"time"

	"cloud.google.com/go/compute/metadata"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/oci"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/go-tpm-tools/cel"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/launcher/agent"
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
	container   containerd.Container
	launchSpec  spec.LauncherSpec
	attestAgent agent.AttestationAgent
	logger      *log.Logger
}

const (
	// HostTokenPath defined the directory that will store attestation tokens
	HostTokenPath                = "/tmp/container_launcher/"
	containerTokenMountPath      = "/run/container_launcher/"
	attestationVerifierTokenFile = "attestation_verifier_claims_token"
)

// Since we only allow one container on a VM, using a deterministic id is probably fine
const (
	containerID = "tee-container"
	snapshotID  = "tee-snapshot"
)

const defaultRefreshMultiplier = 0.9

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
func NewRunner(
	ctx context.Context,
	cdClient *containerd.Client,
	token oauth2.Token,
	launchSpec spec.LauncherSpec,
	mdsClient *metadata.Client,
	tpm io.ReadWriteCloser,
	logger *log.Logger,
) (r *ContainerRunner, finalErr error) {
	verifierClient, err := getRESTClient(ctx, launchSpec.AttestationServiceAddr, launchSpec)
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier client: %v", err)
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

	attestAgent := agent.CreateAttestationAgent(tpm, client.GceAttestationKeyECC, verifierClient, principalFetcher)

	// Make sure we measure failure if we cannot create a Runner
	defer func() {
		if finalErr != nil {
			measureErr := measureFailure(attestAgent, finalErr)
			if measureErr != nil {
				logger.Println(measureErr)
			}
		}
	}()

	if err := measureLaunchSpec(attestAgent, launchSpec); err != nil {
		return nil, fmt.Errorf("failed to measure launch spec events: %v", err)
	}
	image, err := initImage(ctx, cdClient, launchSpec, token, logger)
	if err != nil {
		return nil, err
	}
	if err := measureImage(ctx, attestAgent, image); err != nil {
		return nil, fmt.Errorf("failed to measure image events: %v", err)
	}

	mounts := make([]specs.Mount, 0)
	mounts = appendTokenMounts(mounts)
	envs := parseEnvVars(launchSpec.Envs)
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

	imageLabels, err := getImageLabels(ctx, image)
	if err != nil {
		logger.Printf("Failed to get image OCI labels %v\n", err)
	}

	logger.Printf("Image Labels               : %v\n", imageLabels)
	launchPolicy, err := spec.GetLaunchPolicy(imageLabels)
	if err != nil {
		return nil, err
	}
	if err := launchPolicy.Verify(launchSpec); err != nil {
		return nil, err
	}

	if imageConfig, err := image.Config(ctx); err != nil {
		logger.Println(err)
	} else {
		logger.Printf("Image ID                   : %v\n", imageConfig.Digest)
		logger.Printf("Image Annotations          : %v\n", imageConfig.Annotations)
	}

	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("cannot get hostname: [%w]", err)
	}

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
		),
	)
	if err != nil {
		if container != nil {
			container.Delete(ctx, containerd.WithSnapshotCleanup)
		}
		return nil, fmt.Errorf("failed to create a container: [%w]", err)
	}

	containerSpec, err := container.Spec(ctx)
	if err != nil {
		return nil, err
	}
	// Container process Args length should be strictly longer than the Cmd
	// override length set by the operator, as we want the Entrypoint filed
	// to be mandatory for the image.
	// Roughly speaking, Args = Entrypoint + Cmd
	if len(containerSpec.Process.Args) <= len(launchSpec.Cmd) {
		return nil, fmt.Errorf("length of Args [%d] is shorter or equal to the length of the given Cmd [%d], maybe the Entrypoint is set to empty in the image?", len(containerSpec.Process.Args), len(launchSpec.Cmd))
	}
	if err := measureContainer(attestAgent, containerSpec); err != nil {
		return nil, fmt.Errorf("failed to measure container events: %v", err)
	}

	return &ContainerRunner{
		container,
		launchSpec,
		attestAgent,
		logger,
	}, nil
}

// getRESTClient returns a REST verifier.Client that points to the given address.
// It defaults to the Attestation Verifier instance at
// https://confidentialcomputing.googleapis.com.
func getRESTClient(ctx context.Context, asAddr string, spec spec.LauncherSpec) (verifier.Client, error) {
	httpClient, err := google.DefaultClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %v", err)
	}

	opts := []option.ClientOption{option.WithHTTPClient(httpClient)}
	if asAddr != "" {
		opts = append(opts, option.WithEndpoint(asAddr))
	}

	const defaultRegion = "us-central1"
	restClient, err := rest.NewClient(ctx, spec.ProjectID, defaultRegion, opts...)
	if err != nil {
		return nil, err
	}
	return restClient, nil
}

// parseEnvVars parses the environment variables to the oci format
func parseEnvVars(envVars []spec.EnvVar) []string {
	var result []string
	for _, envVar := range envVars {
		result = append(result, envVar.Name+"="+envVar.Value)
	}
	return result
}

// appendTokenMounts appends the default mount specs for the OIDC token
func appendTokenMounts(mounts []specs.Mount) []specs.Mount {
	m := specs.Mount{}
	m.Destination = containerTokenMountPath
	m.Type = "bind"
	m.Source = HostTokenPath
	m.Options = []string{"rbind", "ro"}

	return append(mounts, m)
}

// Measure container claims specific to the operator-provided LaunchSpec. Should
// be called before downloading the image.
func measureLaunchSpec(a agent.AttestationAgent, ls spec.LauncherSpec) error {
	imgRefEvent := cel.CosTlv{EventType: cel.ImageRefType, EventContent: []byte(ls.ImageRef)}
	if err := a.MeasureEvent(imgRefEvent); err != nil {
		return err
	}
	restartPolicyEvent := cel.CosTlv{EventType: cel.RestartPolicyType, EventContent: []byte(ls.RestartPolicy)}
	if err := a.MeasureEvent(restartPolicyEvent); err != nil {
		return err
	}

	// Measure the overridden Args and Env Vars separately. These will end up
	// being subsets of the Args and Env Vars in measureContainer.
	argEvent := cel.CosTlv{EventType: cel.OverrideArgType}
	for _, arg := range ls.Cmd {
		argEvent.EventContent = []byte(arg)
		if err := a.MeasureEvent(argEvent); err != nil {
			return err
		}
	}

	envEvent := cel.CosTlv{EventType: cel.OverrideEnvType}
	for _, env := range parseEnvVars(ls.Envs) {
		envEvent.EventContent = []byte(env)
		if err := a.MeasureEvent(envEvent); err != nil {
			return err
		}
	}
	return nil
}

// Measure container claims specific to the downloaded image. Should be called
// before creating a container from the downloaded image.
func measureImage(ctx context.Context, a agent.AttestationAgent, image containerd.Image) error {
	digestEvent := cel.CosTlv{EventType: cel.ImageDigestType, EventContent: []byte(image.Target().Digest)}
	if err := a.MeasureEvent(digestEvent); err != nil {
		return err
	}

	if imageConfig, err := image.Config(ctx); err == nil { // if NO error
		idEvent := cel.CosTlv{EventType: cel.ImageIDType, EventContent: []byte(imageConfig.Digest)}
		if err := a.MeasureEvent(idEvent); err != nil {
			return err
		}
	}
	return nil
}

// Measure container claims specific to the constructed container spec. Should
// be called before running the container.
func measureContainer(a agent.AttestationAgent, spec *specs.Spec) error {
	argEvent := cel.CosTlv{EventType: cel.ArgType}
	for _, arg := range spec.Process.Args {
		argEvent.EventContent = []byte(arg)
		if err := a.MeasureEvent(argEvent); err != nil {
			return err
		}
	}

	envEvent := cel.CosTlv{EventType: cel.EnvVarType}
	for _, env := range spec.Process.Env {
		envEvent.EventContent = []byte(env)
		if err := a.MeasureEvent(envEvent); err != nil {
			return err
		}
	}
	return nil
}

// Measure a separator indicating that we failed to launch the container.
func measureFailure(a agent.AttestationAgent, err error) error {
	separator := cel.CosTlv{
		EventType:    cel.LaunchSeparatorType,
		EventContent: []byte(err.Error()),
	}
	return a.MeasureEvent(separator)
}

// Measure final pre-launch separator into the event log. Should be called right
// before executing the container.
func (r *ContainerRunner) measureLaunch(ctx context.Context) error {
	separator := cel.CosTlv{
		EventType:    cel.LaunchSeparatorType,
		EventContent: nil, // Success
	}
	return r.attestAgent.MeasureEvent(separator)
}

// Retrieves an OIDC token from the attestation service, and returns how long
// to wait before attemping to refresh it.
func (r *ContainerRunner) refreshToken(ctx context.Context) (time.Duration, error) {
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

	filepath := path.Join(HostTokenPath, attestationVerifierTokenFile)
	if err = os.WriteFile(filepath, token, 0644); err != nil {
		return 0, fmt.Errorf("failed to write token to container mount source point: %v", err)
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

	return time.Duration(float64(time.Until(claims.ExpiresAt.Time)) * defaultRefreshMultiplier), nil
}

// ctx must be a cancellable context.
func (r *ContainerRunner) fetchAndWriteToken(ctx context.Context) error {
	if err := os.MkdirAll(HostTokenPath, 0744); err != nil {
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
				r.logger.Printf("token refreshing stopped: %v", ctx.Err())
				return
			case <-timer.C:
				// Refresh token.
				duration, err := r.refreshToken(ctx)
				if err != nil {
					r.logger.Printf("failed to refresh attestation service token: %v", err)
					return
				}

				timer.Reset(duration)
			}
		}
	}()

	return nil
}

// Run the container
// Container output will always be redirected to logger writer for now
func (r *ContainerRunner) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := r.fetchAndWriteToken(ctx); err != nil {
		return fmt.Errorf("failed to fetch and write OIDC token: %v", err)
	}

	if err := r.measureLaunch(ctx); err != nil {
		return fmt.Errorf("failed to measure launch events: %v", err)
	}

	for {
		task, err := r.container.NewTask(ctx, cio.NewCreator(cio.WithStreams(nil, r.logger.Writer(), r.logger.Writer())))
		if err != nil {
			return err
		}
		exitStatus, err := task.Wait(ctx)
		if err != nil {
			return err
		}
		r.logger.Println("task started")

		if err := task.Start(ctx); err != nil {
			return err
		}
		status := <-exitStatus

		code, _, err := status.Result()
		if err != nil {
			return err
		}
		task.Delete(ctx)

		r.logger.Printf("task ended with return code %d \n", code)
		if r.launchSpec.RestartPolicy == spec.Always {
			r.logger.Println("restarting task")
		} else if r.launchSpec.RestartPolicy == spec.OnFailure && code != 0 {
			r.logger.Println("restarting task on failure")
		} else {
			break
		}
	}

	return nil
}

func initImage(ctx context.Context, cdClient *containerd.Client, launchSpec spec.LauncherSpec, token oauth2.Token, logger *log.Logger) (containerd.Image, error) {
	var remoteOpt containerd.RemoteOpt
	if token.Valid() {
		remoteOpt = containerd.WithResolver(Resolver(token.AccessToken))
	} else {
		logger.Println("invalid auth token, will use empty auth")
	}

	image, err := cdClient.Pull(ctx, launchSpec.ImageRef, containerd.WithPullUnpack, remoteOpt)
	if err != nil {
		return nil, fmt.Errorf("cannot pull image: %w", err)
	}
	if image.Name() != launchSpec.ImageRef {
		return nil, fmt.Errorf(
			"created images has name %q, expected supplied image reference %q",
			image.Name(),
			launchSpec.ImageRef,
		)
	}
	return image, nil
}

func getImageLabels(ctx context.Context, image containerd.Image) (map[string]string, error) {
	// TODO(jiankun): Switch to containerd's WithImageConfigLabels()
	ic, err := image.Config(ctx)
	if err != nil {
		return nil, err
	}
	switch ic.MediaType {
	case v1.MediaTypeImageConfig, images.MediaTypeDockerSchema2Config:
		p, err := content.ReadBlob(ctx, image.ContentStore(), ic)
		if err != nil {
			return nil, err
		}
		var ociimage v1.Image
		if err := json.Unmarshal(p, &ociimage); err != nil {
			return nil, err
		}
		return ociimage.Config.Labels, nil
	}
	return nil, fmt.Errorf("unknown image config media type %s", ic.MediaType)
}

// Close the container runner
func (r *ContainerRunner) Close(ctx context.Context) {
	// Exit gracefully:
	// Delete container and close connection to attestation service.
	r.container.Delete(ctx, containerd.WithSnapshotCleanup)
}
