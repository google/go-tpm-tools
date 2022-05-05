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
	"github.com/google/go-tpm-tools/launcher/spec"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/oauth2"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	idTokenEndpoint = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateIdToken"
)

type attestationAgent interface {
	MeasureEvent(cel.Content) error
	Attest(context.Context) ([]byte, error)
}

// ContainerRunner contains information about the container settings
type ContainerRunner struct {
	container   containerd.Container
	launchSpec  spec.LauncherSpec
	attestConn  *grpc.ClientConn
	attestAgent attestationAgent
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

func fetchImpersonatedToken(ctx context.Context, serviceAccounts []string, audience string, opts ...option.ClientOption) ([]byte, error) {
	if len(serviceAccounts) < 1 {
		return nil, fmt.Errorf("no service accounts provided")
	}

	log.Printf("target is: %v", serviceAccounts[len(serviceAccounts)-1])

	config := impersonate.IDTokenConfig{
		Audience:        audience,
		TargetPrincipal: serviceAccounts[len(serviceAccounts)-1],
		IncludeEmail:    true,
		Delegates:       serviceAccounts[:len(serviceAccounts)-1],
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
func NewRunner(ctx context.Context, cdClient *containerd.Client, token oauth2.Token, launchSpec spec.LauncherSpec, mdsClient *metadata.Client, tpm io.ReadWriteCloser) (*ContainerRunner, error) {
	image, err := initImage(ctx, cdClient, launchSpec, token)
	if err != nil {
		return nil, err
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

	log.Printf("Operator Input Image Ref   : %v\n", image.Name())
	log.Printf("Image Digest               : %v\n", image.Target().Digest)
	log.Printf("Operator Override Env Vars : %v\n", envs)
	log.Printf("Operator Override Cmd      : %v\n", launchSpec.Cmd)

	imagelabels, err := getImageLabels(ctx, image)
	if err != nil {
		log.Printf("Failed to get image OCI labels %v\n", err)
	}
	log.Printf("Image Labels               : %v\n", imagelabels)

	if imageConfig, err := image.Config(ctx); err != nil {
		log.Println(err)
	} else {
		log.Printf("Image ID                   : %v\n", imageConfig.Digest)
		log.Printf("Image Annotations          : %v\n", imageConfig.Annotations)
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

	// TODO(b/212586174): Dial with secure credentials.
	opt := grpc.WithTransportCredentials(insecure.NewCredentials())
	conn, err := grpc.Dial(launchSpec.AttestationServiceAddr, opt)
	if err != nil {
		return nil, fmt.Errorf("failed to open connection to attestation service: %v", err)
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

		// Fetch impersonated ID token.
		if len(launchSpec.ImpersonateServiceAccounts) != 0 {
			idToken, err := fetchImpersonatedToken(ctx, launchSpec.ImpersonateServiceAccounts, audience)
			if err != nil {
				return nil, fmt.Errorf("failed to get impersonated tokens: %w", err)
			}

			tokens = append(tokens, idToken)
		}
		return tokens, nil
	}

	return &ContainerRunner{
		container,
		launchSpec,
		conn,
		CreateAttestationAgent(tpm, client.GceAttestationKeyECC, conn, principalFetcher),
	}, nil
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
	r.attestAgent.MeasureEvent(cel.CosTlv{EventType: cel.RestartPolicyType, EventContent: []byte(r.launchSpec.RestartPolicy)})
	if imageConfig, err := image.Config(ctx); err == nil { // if NO error
		if err := r.attestAgent.MeasureEvent(cel.CosTlv{EventType: cel.ImageIDType, EventContent: []byte(imageConfig.Digest)}); err != nil {
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
	return nil
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

	return time.Duration(float64(time.Until(claims.ExpiresAt.Time)) * defaultRefreshMultiplier), nil
}

// ctx must be a cancellable context.
func (r *ContainerRunner) fetchAndWriteToken(ctx context.Context) error {
	if err := os.MkdirAll(HostTokenPath, 0744); err != nil {
		log.Fatal(err)
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
				log.Printf("token refreshing stopped: %v", ctx.Err())
				return
			case <-timer.C:
				// Refresh token.
				duration, err := r.refreshToken(ctx)
				if err != nil {
					log.Printf("failed to refresh attestation service token: %v", err)
					return
				}

				timer.Reset(duration)
			}
		}
	}()

	return nil
}

// Run the container
// Doesn't support container restart yet
// Container output will always be redirected to stdio for now
func (r *ContainerRunner) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := r.measureContainerClaims(ctx); err != nil {
		return fmt.Errorf("failed to measure container claims: %v", err)
	}

	if err := r.fetchAndWriteToken(ctx); err != nil {
		return fmt.Errorf("failed to fetch and write OIDC token: %v", err)
	}

	task, err := r.container.NewTask(ctx, cio.NewCreator(cio.WithStdio))
	if err != nil {
		return err
	}
	defer task.Delete(ctx)

	exitStatus, err := task.Wait(ctx)
	if err != nil {
		return err
	}
	log.Println("task started")

	if err := task.Start(ctx); err != nil {
		return err
	}
	status := <-exitStatus

	code, _, err := status.Result()
	if err != nil {
		return err
	}

	if code != 0 {
		return fmt.Errorf("task ended with non-zero return code %d", code)
	}

	return nil
}

func initImage(ctx context.Context, cdClient *containerd.Client, launchSpec spec.LauncherSpec, token oauth2.Token) (containerd.Image, error) {
	if launchSpec.UseLocalImage {
		image, err := cdClient.GetImage(ctx, launchSpec.ImageRef)
		if err != nil {
			return nil, fmt.Errorf("cannot get local image: [%w]", err)
		}
		return image, nil
	}

	var remoteOpt containerd.RemoteOpt
	if token.Valid() {
		remoteOpt = containerd.WithResolver(Resolver(token.AccessToken))
	} else {
		log.Println("invalid auth token, will use empty auth")
	}

	image, err := cdClient.Pull(ctx, launchSpec.ImageRef, containerd.WithPullUnpack, remoteOpt)
	if err != nil {
		return nil, fmt.Errorf("cannot pull image: %w", err)
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
	r.attestConn.Close()
}
