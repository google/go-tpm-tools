package launcher

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"strconv"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/defaults"
	"github.com/containerd/containerd/namespaces"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/go-tpm-tools/cel"
	"github.com/google/go-tpm-tools/launcher/launcherfile"
	"github.com/google/go-tpm-tools/launcher/spec"
	"golang.org/x/oauth2"
	"google.golang.org/api/option"
)

const (
	idTokenEndpoint = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateIdToken"
)

// Fake attestation agent.
type fakeAttestationAgent struct {
	measureEventFunc func(cel.Content) error
	attestFunc       func(context.Context) ([]byte, error)
}

func (f *fakeAttestationAgent) MeasureEvent(event cel.Content) error {
	if f.measureEventFunc != nil {
		return f.measureEventFunc(event)
	}

	return fmt.Errorf("unimplemented")
}

func (f *fakeAttestationAgent) Attest(ctx context.Context) ([]byte, error) {
	if f.attestFunc != nil {
		return f.attestFunc(ctx)
	}

	return nil, fmt.Errorf("unimplemented")
}

func createJWT(t *testing.T, ttl time.Duration) []byte {
	return createJWTWithID(t, "test token", ttl)
}

func createJWTWithID(t *testing.T, id string, ttl time.Duration) []byte {
	t.Helper()

	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Error creating token key: %v", err)
	}

	now := jwt.TimeFunc()
	claims := &jwt.RegisteredClaims{
		ID:        id,
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
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
			attestFunc: func(context.Context) ([]byte, error) {
				return expectedToken, nil
			},
		},
		logger: log.Default(),
	}

	if err := os.MkdirAll(launcherfile.HostTmpPath, 0744); err != nil {
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

func TestRefreshTokenError(t *testing.T) {
	if err := os.MkdirAll(launcherfile.HostTmpPath, 0744); err != nil {
		t.Fatalf("Error creating host token path directory: %v", err)
	}

	testcases := []struct {
		name  string
		agent *fakeAttestationAgent
	}{
		{
			name: "Attest fails",
			agent: &fakeAttestationAgent{
				attestFunc: func(context.Context) ([]byte, error) {
					return nil, errors.New("attest error")
				},
			},
		},
		{
			name: "Attest returns expired token",
			agent: &fakeAttestationAgent{
				attestFunc: func(context.Context) ([]byte, error) {
					return createJWT(t, -5*time.Second), nil
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			runner := ContainerRunner{
				attestAgent: tc.agent,
				logger:      log.Default(),
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
			attestFunc: func(context.Context) ([]byte, error) {
				return expectedToken, nil
			},
		},
		logger: log.Default(),
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
	successfulAttestFunc := func(context.Context) ([]byte, error) {
		return expectedToken, nil
	}

	errorAttestFunc := func(context.Context) ([]byte, error) {
		return nil, errors.New("attest unsuccessful")
	}

	runner := ContainerRunner{
		attestAgent: &fakeAttestationAgent{attestFunc: successfulAttestFunc},
		logger:      log.Default(),
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

	// Change attest agent to return error.
	runner.attestAgent = &fakeAttestationAgent{attestFunc: errorAttestFunc}

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
	attestFunc := func(context.Context) ([]byte, error) {
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
		logger:      log.Default(),
	}
	if err := runner.fetchAndWriteTokenWithRetry(ctx, testRetryPolicyThreeTimes()); err != nil {
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

	ttl := 5 * time.Second

	runner := ContainerRunner{
		attestAgent: &fakeAttestationAgent{
			attestFunc: func(context.Context) ([]byte, error) {
				return expectedToken, nil
			},
		},
		logger: log.Default(),
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

	// Change attest agent to return new token.
	expectedRefreshedToken := createJWT(t, 10*time.Second)
	runner.attestAgent = &fakeAttestationAgent{
		attestFunc: func(context.Context) ([]byte, error) {
			return expectedRefreshedToken, nil
		},
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

type testRoundTripper struct {
	roundTripFunc func(*http.Request) *http.Response
}

func (t *testRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.roundTripFunc(req), nil
}

type idTokenResp struct {
	Token string `json:"token"`
}

func TestFetchImpersonatedToken(t *testing.T) {
	expectedEmail := "test2@google.com"

	expectedToken := []byte("test_token")

	expectedURL := fmt.Sprintf(idTokenEndpoint, expectedEmail)
	client := &http.Client{
		Transport: &testRoundTripper{
			roundTripFunc: func(req *http.Request) *http.Response {
				if req.URL.String() != expectedURL {
					t.Errorf("HTTP call was not made to a endpoint: got %v, want %v", req.URL.String(), expectedURL)
				}

				resp := idTokenResp{
					Token: string(expectedToken),
				}

				respBody, err := json.Marshal(resp)
				if err != nil {
					t.Fatalf("Unable to marshal HTTP response: %v", err)
				}

				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(bytes.NewBuffer(respBody)),
				}
			},
		},
	}

	token, err := fetchImpersonatedToken(context.Background(), expectedEmail, "test_aud", option.WithHTTPClient(client))
	if err != nil {
		t.Fatalf("fetchImpersonatedToken returned error: %v", err)
	}

	if !bytes.Equal(token, expectedToken) {
		t.Errorf("fetchImpersonatedToken did not return expected token: got %v, want %v", token, expectedToken)
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
