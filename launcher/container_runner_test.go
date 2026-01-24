package launcher

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
	"path"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/defaults"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/oci"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/go-cmp/cmp"
	gecel "github.com/google/go-eventlog/cel"
	"github.com/google/go-tpm-tools/cel"
	"github.com/google/go-tpm-tools/launcher/agent"
	"github.com/google/go-tpm-tools/launcher/internal/logging"
	"github.com/google/go-tpm-tools/launcher/launcherfile"
	"github.com/google/go-tpm-tools/launcher/spec"
	"github.com/google/go-tpm-tools/verifier"
	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/oauth2"
)

const (
	idTokenEndpoint = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateIdToken"
)

// Fake attestation agent.
type fakeAttestationAgent struct {
	measureEventFunc func(gecel.Content) error
	attestFunc       func(context.Context, agent.AttestAgentOpts) ([]byte, error)
	sigsCache        []string
	sigsFetcherFunc  func(context.Context) []string

	// attMu sits on top of attempts field and protects attempts.
	attMu    sync.Mutex
	attempts int
}

func (f *fakeAttestationAgent) MeasureEvent(event gecel.Content) error {
	if f.measureEventFunc != nil {
		return f.measureEventFunc(event)
	}

	return fmt.Errorf("unimplemented")
}

func (f *fakeAttestationAgent) Attest(ctx context.Context, _ agent.AttestAgentOpts) ([]byte, error) {
	if f.attestFunc != nil {
		return f.attestFunc(ctx, agent.AttestAgentOpts{})
	}

	return nil, fmt.Errorf("unimplemented")
}

func (f *fakeAttestationAgent) AttestWithClient(_ context.Context, _ agent.AttestAgentOpts, _ verifier.Client) ([]byte, error) {
	return nil, fmt.Errorf("unimplemented")
}

// Refresh simulates the behavior of an actual agent.
func (f *fakeAttestationAgent) Refresh(ctx context.Context) error {
	if f.sigsFetcherFunc != nil {
		f.sigsCache = f.sigsFetcherFunc(ctx)
	}
	return nil
}

func (f *fakeAttestationAgent) Close() error {
	return nil
}

type fakeClaims struct {
	jwt.RegisteredClaims
	Signatures []string
}

func createJWT(t *testing.T, ttl time.Duration) []byte {
	return createJWTWithID(t, "test token", ttl)
}

func createJWTWithID(t *testing.T, id string, ttl time.Duration) []byte {
	now := jwt.TimeFunc()
	claims := &jwt.RegisteredClaims{
		ID:        id,
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
	}

	return createSignedToken(t, claims)
}

func createJWTWithSignatures(t *testing.T, signatures []string) []byte {
	now := jwt.TimeFunc()
	ttl := 5 * time.Second
	id := "signature token"
	claims := &fakeClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        id,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		Signatures: signatures,
	}
	return createSignedToken(t, claims)
}

func createSignedToken(t *testing.T, claims jwt.Claims) []byte {
	t.Helper()

	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Error creating token key: %v", err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(privkey)
	if err != nil {
		t.Fatalf("Error creating signed string: %v", err)
	}

	return []byte(signed)
}

func extractJWTClaims(t *testing.T, token []byte) *jwt.RegisteredClaims {
	claims := &jwt.RegisteredClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(string(token), claims)
	if err != nil {
		t.Fatalf("failed to parse JWT: %v", token)
	}
	return claims
}

func TestRefreshToken(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ttl := 5 * time.Second
	expectedToken := createJWT(t, ttl)

	runner := ContainerRunner{
		attestAgent: &fakeAttestationAgent{
			attestFunc: func(context.Context, agent.AttestAgentOpts) ([]byte, error) {
				return expectedToken, nil
			},
		},
		logger: logging.SimpleLogger(),
	}

	if err := os.MkdirAll(launcherfile.HostTmpPath, 0755); err != nil {
		t.Fatalf("Error creating host token path directory: %v", err)
	}

	refreshTime, err := runner.refreshToken(ctx)
	if err != nil {
		t.Fatalf("refreshToken returned with error: %v", err)
	}

	filepath := path.Join(launcherfile.HostTmpPath, launcherfile.AttestationVerifierTokenFilename)
	data, err := os.ReadFile(filepath)
	if err != nil {
		t.Fatalf("Failed to read from %s: %v", filepath, err)
	}

	if !bytes.Equal(data, expectedToken) {
		t.Errorf("Initial token written to file does not match expected token: got %v, want %v", data, expectedToken)
	}

	// Expect refreshTime to be no greater than expectedTTL.
	if refreshTime >= time.Duration(float64(ttl)) {
		t.Errorf("Refresh time cannot exceed ttl: got %v, expect no greater than %v", refreshTime, time.Duration(float64(ttl)))
	}
}

// TestRefreshTokenWithSignedContainerCacheEnabled checks `refreshToken` updates the default token when signatures get updated.
func TestRefreshTokenWithSignedContainerCacheEnabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	oldCache := []string{"old sigs cache"}
	fakeAgent := &fakeAttestationAgent{
		sigsFetcherFunc: func(context.Context) []string {
			return oldCache
		},
	}
	fakeAgent.attestFunc = func(context.Context, agent.AttestAgentOpts) ([]byte, error) {
		return createJWTWithSignatures(t, fakeAgent.sigsCache), nil
	}

	runner := ContainerRunner{
		attestAgent: fakeAgent,
		logger:      logging.SimpleLogger(),
	}

	if err := os.MkdirAll(launcherfile.HostTmpPath, 0755); err != nil {
		t.Fatalf("Error creating host token path directory: %v", err)
	}

	_, err := runner.refreshToken(ctx)
	if err != nil {
		t.Fatalf("refreshToken returned with error: %v", err)
	}

	// Simulate adding signatures.
	newCache := []string{"old sigs cache", "new sigs cache"}
	fakeAgent.sigsFetcherFunc = func(context.Context) []string {
		return newCache
	}

	// Refresh token again to get the updated token.
	_, err = runner.refreshToken(ctx)
	if err != nil {
		t.Fatalf("refreshToken returned with error: %v", err)
	}

	// Read the token to check if claims contain the updated signatures.
	filepath := path.Join(launcherfile.HostTmpPath, launcherfile.AttestationVerifierTokenFilename)
	token, err := os.ReadFile(filepath)
	if err != nil {
		t.Fatalf("Failed to read from %s: %v", filepath, err)
	}

	gotClaims := &fakeClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(string(token), gotClaims)
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}

	if gotSignatures, wantSignatures := gotClaims.Signatures, newCache; !cmp.Equal(gotSignatures, wantSignatures) {
		t.Errorf("Updated token written to file does not contain expected signatures: got %v, want %v", gotSignatures, wantSignatures)
	}
}

func TestRefreshTokenError(t *testing.T) {
	if err := os.MkdirAll(launcherfile.HostTmpPath, 0755); err != nil {
		t.Fatalf("Error creating host token path directory: %v", err)
	}

	testcases := []struct {
		name  string
		agent *fakeAttestationAgent
	}{
		{
			name: "Attest fails",
			agent: &fakeAttestationAgent{
				attestFunc: func(context.Context, agent.AttestAgentOpts) ([]byte, error) {
					return nil, errors.New("attest error")
				},
			},
		},
		{
			name: "Attest returns expired token",
			agent: &fakeAttestationAgent{
				attestFunc: func(context.Context, agent.AttestAgentOpts) ([]byte, error) {
					return createJWT(t, -5*time.Second), nil
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			runner := ContainerRunner{
				attestAgent: tc.agent,
				logger:      logging.SimpleLogger(),
			}

			if _, err := runner.refreshToken(context.Background()); err == nil {
				t.Error("refreshToken succeeded, expected error.")
			}

		})
	}
}

func TestFetchAndWriteTokenSucceeds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	expectedToken := createJWT(t, 5*time.Second)

	runner := ContainerRunner{
		attestAgent: &fakeAttestationAgent{
			attestFunc: func(context.Context, agent.AttestAgentOpts) ([]byte, error) {
				return expectedToken, nil
			},
		},
		logger: logging.SimpleLogger(),
	}

	if err := runner.fetchAndWriteToken(ctx); err != nil {
		t.Fatalf("fetchAndWriteToken failed: %v", err)
	}

	filepath := path.Join(launcherfile.HostTmpPath, launcherfile.AttestationVerifierTokenFilename)
	data, err := os.ReadFile(filepath)
	if err != nil {
		t.Fatalf("Failed to read from %s: %v", filepath, err)
	}

	if !bytes.Equal(data, expectedToken) {
		t.Errorf("Token written to file does not match expected token: got %v, want %v", data, expectedToken)
	}
}

func TestTokenIsNotChangedIfRefreshFails(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	expectedToken := createJWT(t, 5*time.Second)
	ttl := 5 * time.Second

	attestAgent := &fakeAttestationAgent{}
	attestAgent.attestFunc = func(context.Context, agent.AttestAgentOpts) ([]byte, error) {
		attestAgent.attMu.Lock()
		defer func() {
			attestAgent.attempts = attestAgent.attempts + 1
			attestAgent.attMu.Unlock()
		}()
		if attestAgent.attempts%2 == 0 {
			return expectedToken, nil
		}
		return nil, errors.New("attest unsuccessful")
	}

	runner := ContainerRunner{
		attestAgent: attestAgent,
		logger:      logging.SimpleLogger(),
	}

	if err := runner.fetchAndWriteToken(ctx); err != nil {
		t.Fatalf("fetchAndWriteToken failed: %v", err)
	}

	filepath := path.Join(launcherfile.HostTmpPath, launcherfile.AttestationVerifierTokenFilename)
	data, err := os.ReadFile(filepath)
	if err != nil {
		t.Fatalf("Failed to read from %s: %v", filepath, err)
	}

	if !bytes.Equal(data, expectedToken) {
		t.Errorf("Initial token written to file does not match expected token: got %v, want %v", data, expectedToken)
	}

	time.Sleep(ttl)

	data, err = os.ReadFile(filepath)
	if err != nil {
		t.Fatalf("Failed to read from %s: %v", filepath, err)
	}

	if !bytes.Equal(data, expectedToken) {
		t.Errorf("Expected token to remain the same after unsuccessful refresh attempt: got %v", data)
	}
}

// testRetryPolicy tries the operation at the following times:
// t=0s, .5s, 1.25s. It is canceled before the fourth try.
func testRetryPolicyThreeTimes() *backoff.ExponentialBackOff {
	expBack := backoff.NewExponentialBackOff()
	expBack.InitialInterval = 500 * time.Millisecond
	expBack.RandomizationFactor = 0
	expBack.Multiplier = 1.5
	expBack.MaxInterval = 1 * time.Second
	expBack.MaxElapsedTime = 2249 * time.Millisecond
	return expBack
}

func TestTokenRefreshRetryPolicyFail(t *testing.T) {
	testRetryPolicyWithNTries(t, 4 /*numTries*/, false /*expectRefresh*/)
}

func TestTokenRefreshRetryPolicy(t *testing.T) {
	// Test retry policy tries 3 times.
	for numTries := 1; numTries <= 3; numTries++ {
		t.Run("RetryPolicyWith"+strconv.Itoa(numTries)+"Tries",
			func(t *testing.T) { testRetryPolicyWithNTries(t, numTries /*numTries*/, true /*expectRefresh*/) })
	}
}

func testRetryPolicyWithNTries(t *testing.T, numTries int, expectRefresh bool) {
	strNum := strconv.Itoa(numTries)
	t.Logf("testing with %d tries", numTries)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	expectedInitialToken := createJWTWithID(t, "initial token"+strNum, 5*time.Second)
	expectedRefreshToken := createJWTWithID(t, "refresh token"+strNum, 100*time.Second)
	// Wait the initial token's 5s plus a second per retry (MaxInterval).
	ttl := time.Duration(numTries)*time.Second + 5*time.Second
	retry := -1
	attestFunc := func(context.Context, agent.AttestAgentOpts) ([]byte, error) {
		retry++
		// Success on the initial fetch (subsequent calls use refresher goroutine).
		if retry == 0 {
			return expectedInitialToken, nil
		}
		if retry == numTries {
			return expectedRefreshToken, nil
		}
		return nil, errors.New("attest unsuccessful")
	}
	runner := ContainerRunner{
		attestAgent: &fakeAttestationAgent{attestFunc: attestFunc},
		logger:      logging.SimpleLogger(),
	}
	if err := runner.fetchAndWriteTokenWithRetry(ctx, testRetryPolicyThreeTimes); err != nil {
		t.Fatalf("fetchAndWriteTokenWithRetry failed: %v", err)
	}
	filepath := path.Join(launcherfile.HostTmpPath, launcherfile.AttestationVerifierTokenFilename)
	data, err := os.ReadFile(filepath)
	if err != nil {
		t.Fatalf("failed to read from %s: %v", filepath, err)
	}

	if !bytes.Equal(data, expectedInitialToken) {
		gotClaims := extractJWTClaims(t, data)
		wantClaims := extractJWTClaims(t, expectedInitialToken)
		t.Errorf("initial token written to file does not match expected token: got ID %v, want ID %v", gotClaims.ID, wantClaims.ID)
	}
	time.Sleep(ttl)

	data, err = os.ReadFile(filepath)
	if err != nil {
		t.Fatalf("failed to read from %s: %v", filepath, err)
	}

	// No refresh: the token should match initial token.
	if !expectRefresh && !bytes.Equal(data, expectedInitialToken) {
		gotClaims := extractJWTClaims(t, data)
		wantClaims := extractJWTClaims(t, expectedInitialToken)
		t.Errorf("token refresher should fail and received token should be the initial token: got ID %v, want ID %v", gotClaims.ID, wantClaims.ID)
	}

	// Should Refresh: the token should match refreshed token.
	if expectRefresh && !bytes.Equal(data, expectedRefreshToken) {
		gotClaims := extractJWTClaims(t, data)
		wantClaims := extractJWTClaims(t, expectedRefreshToken)
		t.Errorf("refreshed token did not match expected token: got ID %v, want ID %v", gotClaims.ID, wantClaims.ID)
	}
}

func TestFetchAndWriteTokenWithTokenRefresh(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	expectedToken := createJWT(t, 5*time.Second)
	expectedRefreshedToken := createJWT(t, 10*time.Second)

	ttl := 5 * time.Second

	attestAgent := &fakeAttestationAgent{}
	attestAgent.attestFunc = func(context.Context, agent.AttestAgentOpts) ([]byte, error) {
		attestAgent.attMu.Lock()
		defer func() {
			attestAgent.attempts = attestAgent.attempts + 1
			attestAgent.attMu.Unlock()
		}()
		if attestAgent.attempts%2 == 0 {
			return expectedToken, nil
		}
		return expectedRefreshedToken, nil
	}
	runner := ContainerRunner{
		attestAgent: attestAgent,
		logger:      logging.SimpleLogger(),
	}

	if err := runner.fetchAndWriteToken(ctx); err != nil {
		t.Fatalf("fetchAndWriteToken failed: %v", err)
	}

	filepath := path.Join(launcherfile.HostTmpPath, launcherfile.AttestationVerifierTokenFilename)
	data, err := os.ReadFile(filepath)
	if err != nil {
		t.Fatalf("Failed to read from %s: %v", filepath, err)
	}

	if !bytes.Equal(data, expectedToken) {
		t.Errorf("Initial token written to file does not match expected token: got %v, want %v", data, expectedToken)
	}

	// Check that token has not been refreshed yet.
	data, err = os.ReadFile(filepath)
	if err != nil {
		t.Fatalf("Failed to read from %s: %v", filepath, err)
	}

	if !bytes.Equal(data, expectedToken) {
		t.Errorf("Token unexpectedly refreshed: got %v, want %v", data, expectedRefreshedToken)
	}

	time.Sleep(ttl)

	// Check that token has changed.
	data, err = os.ReadFile(filepath)
	if err != nil {
		t.Fatalf("Failed to read from %s: %v", filepath, err)
	}

	if !bytes.Equal(data, expectedRefreshedToken) {
		t.Errorf("Refreshed token written to file does not match expected token: got %v, want %v", data, expectedRefreshedToken)
	}
}

func TestGetNextRefresh(t *testing.T) {
	// 0 <= random < 1.
	for _, randNum := range []float64{0, .1415926, .5, .75, .999999999} {
		// expiration should always be >0.
		// 0 or negative expiration means the token has already expired.
		for _, expInt := range []int64{1, 10, 100, 1000, 10000, 1000000} {
			expDuration := time.Duration(expInt)
			next := getNextRefreshFromExpiration(expDuration, randNum)
			if next >= expDuration {
				t.Errorf("getNextRefreshFromExpiration(%v, %v) = %v next refresh. expected %v (next refresh) < %v (expiration)",
					expDuration, randNum, next, next, expDuration)
			}
		}
	}
}

func TestInitImageDockerPublic(t *testing.T) {
	// testing image fetching using a dummy token and a docker repo url
	containerdClient, err := containerd.New(defaults.DefaultAddress)
	if err != nil {
		t.Skipf("test needs containerd daemon: %v", err)
	}

	ctx := namespaces.WithNamespace(context.Background(), "test")
	// This is a "valid" token (formatwise)
	validToken := oauth2.Token{AccessToken: "000000", Expiry: time.Now().Add(time.Hour)}
	if _, err := initImage(ctx, containerdClient, spec.LaunchSpec{ImageRef: "docker.io/library/hello-world:latest"}, validToken); err != nil {
		t.Error(err)
	} else {
		if err := containerdClient.ImageService().Delete(ctx, "docker.io/library/hello-world:latest"); err != nil {
			t.Error(err)
		}
	}

	invalidToken := oauth2.Token{}
	if _, err := initImage(ctx, containerdClient, spec.LaunchSpec{ImageRef: "docker.io/library/hello-world:latest"}, invalidToken); err != nil {
		t.Error(err)
	} else {
		if err := containerdClient.ImageService().Delete(ctx, "docker.io/library/hello-world:latest"); err != nil {
			t.Error(err)
		}
	}
}

func TestMeasureCELEvents(t *testing.T) {
	ctx := context.Background()
	fakeContainer := &fakeContainer{
		image: &fakeImage{
			name:   "fake image name",
			digest: "fake digest",
			id:     "fake id",
		},
		args: []string{"fake args"},
		env:  []string{"fake env"},
	}

	testCases := []struct {
		name          string
		wantCELEvents []cel.CosType
		launchSpec    spec.LaunchSpec
	}{
		{
			name: "measure full container events and launch separator event",
			wantCELEvents: []cel.CosType{
				cel.ImageRefType,
				cel.ImageDigestType,
				cel.RestartPolicyType,
				cel.ImageIDType,
				cel.ArgType,
				cel.EnvVarType,
				cel.OverrideEnvType,
				cel.OverrideArgType,
				cel.MemoryMonitorType,
				cel.LaunchSeparatorType,
			},
			launchSpec: spec.LaunchSpec{
				Envs: []spec.EnvVar{{Name: "hello", Value: "world"}},
				Cmd:  []string{"hello world"},
			},
		},
		{
			name: "measure partial container events, memory monitoring event, and launch separator event",
			wantCELEvents: []cel.CosType{
				cel.ImageRefType,
				cel.ImageDigestType,
				cel.RestartPolicyType,
				cel.ImageIDType,
				cel.ArgType,
				cel.EnvVarType,
				cel.MemoryMonitorType,
				cel.LaunchSeparatorType,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotEvents := []cel.CosType{}

			fakeAgent := &fakeAttestationAgent{
				measureEventFunc: func(content gecel.Content) error {
					got, _ := content.TLV()
					tlv := &gecel.TLV{}
					tlv.UnmarshalBinary(got.Value)
					gotEvents = append(gotEvents, cel.CosType(tlv.Type))
					return nil
				},
			}

			r := ContainerRunner{
				attestAgent: fakeAgent,
				container:   fakeContainer,
				launchSpec:  tc.launchSpec,
				logger:      logging.SimpleLogger(),
			}

			if err := r.measureCELEvents(ctx); err != nil {
				t.Errorf("failed to measureCELEvents: %v", err)
			}

			if !cmp.Equal(gotEvents, tc.wantCELEvents) {
				t.Errorf("failed to measure CEL events, got %v, but want %v", gotEvents, tc.wantCELEvents)
			}
		})
	}
}

func TestPullImageWithRetries(t *testing.T) {
	testCases := []struct {
		name        string
		imagePuller func(int) (containerd.Image, error)
		wantPass    bool
	}{
		{
			name:        "success with single attempt",
			imagePuller: func(int) (containerd.Image, error) { return &fakeImage{}, nil },
			wantPass:    true,
		},
		{
			name: "failure then success",
			imagePuller: func(attempts int) (containerd.Image, error) {
				if attempts%2 == 1 {
					return nil, errors.New("fake error")
				}
				return &fakeImage{}, nil
			},
			wantPass: true,
		},
		{
			name: "failure with attempts exceeded",
			imagePuller: func(int) (containerd.Image, error) {
				return nil, errors.New("fake error")
			},
			wantPass: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			retryPolicy := func() backoff.BackOff {
				b := backoff.NewExponentialBackOff()
				return backoff.WithMaxRetries(b, 2)
			}

			attempts := 0
			_, err := pullImageWithRetries(
				func() (containerd.Image, error) {
					attempts++
					return tc.imagePuller(attempts)
				},
				retryPolicy)
			if gotPass := (err == nil); gotPass != tc.wantPass {
				t.Errorf("pullImageWithRetries failed, got %v, but want %v", gotPass, tc.wantPass)
			}
		})
	}
}

// This ensures fakeContainer implements containerd.Container interface.
var _ containerd.Container = &fakeContainer{}

// This ensures fakeImage implements containerd.Image interface.
var _ containerd.Image = &fakeImage{}

type fakeContainer struct {
	containerd.Container
	image containerd.Image
	args  []string
	env   []string
}

func (c *fakeContainer) Image(context.Context) (containerd.Image, error) {
	return c.image, nil
}

func (c *fakeContainer) Spec(context.Context) (*oci.Spec, error) {
	return &oci.Spec{Process: &specs.Process{Args: c.args, Env: c.env}}, nil
}

type fakeImage struct {
	containerd.Image
	name   string
	digest digest.Digest
	id     digest.Digest
}

func (i *fakeImage) Name() string {
	return i.name
}

func (i *fakeImage) Target() v1.Descriptor {
	return v1.Descriptor{Digest: i.digest}
}

func (i *fakeImage) Config(_ context.Context) (v1.Descriptor, error) {
	return v1.Descriptor{Digest: i.id}, nil
}
