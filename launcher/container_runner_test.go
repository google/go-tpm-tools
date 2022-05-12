package main

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
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/go-tpm-tools/cel"
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

func createJWTToken(t *testing.T, ttl time.Duration) []byte {
	t.Helper()

	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Error creating token key: %v", err)
	}

	now := jwt.TimeFunc()
	claims := &jwt.RegisteredClaims{
		ID:        "test token",
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

func TestRefreshToken(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ttl := 5 * time.Second
	expectedToken := createJWTToken(t, ttl)

	runner := ContainerRunner{
		attestAgent: &fakeAttestationAgent{
			attestFunc: func(context.Context) ([]byte, error) {
				return expectedToken, nil
			},
		},
		logger: log.Default(),
	}

	if err := os.MkdirAll(HostTokenPath, 0744); err != nil {
		t.Fatalf("Error creating host token path directory: %v", err)
	}

	refreshTime, err := runner.refreshToken(ctx)
	if err != nil {
		t.Fatalf("refreshToken returned with error: %v", err)
	}

	filepath := path.Join(HostTokenPath, attestationVerifierTokenFile)
	data, err := os.ReadFile(filepath)
	if err != nil {
		t.Fatalf("Failed to read from %s: %v", filepath, err)
	}

	if !bytes.Equal(data, expectedToken) {
		t.Errorf("Initial token written to file does not match expected token: got %v, want %v", data, expectedToken)
	}

	// Expect refreshTime to be no greater than expectedTTL * refreshRatio.
	if refreshTime >= time.Duration(float64(ttl)*defaultRefreshMultiplier) {
		t.Errorf("Refresh time cannot exceed ttl*refreshRato: got %v, expect no greater than %v", refreshTime, time.Duration(float64(ttl)*defaultRefreshMultiplier))
	}
}

func TestRefreshTokenError(t *testing.T) {
	if err := os.MkdirAll(HostTokenPath, 0744); err != nil {
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
					return createJWTToken(t, -5*time.Second), nil
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

	expectedToken := createJWTToken(t, 5*time.Second)

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

	filepath := path.Join(HostTokenPath, attestationVerifierTokenFile)
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

	expectedToken := createJWTToken(t, 5*time.Second)
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

	filepath := path.Join(HostTokenPath, attestationVerifierTokenFile)
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

func TestFetchAndWriteTokenWithTokenRefresh(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	expectedToken := createJWTToken(t, 5*time.Second)

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

	filepath := path.Join(HostTokenPath, attestationVerifierTokenFile)
	data, err := os.ReadFile(filepath)
	if err != nil {
		t.Fatalf("Failed to read from %s: %v", filepath, err)
	}

	if !bytes.Equal(data, expectedToken) {
		t.Errorf("Initial token written to file does not match expected token: got %v, want %v", data, expectedToken)
	}

	// Change attest agent to return new token.
	expectedRefreshedToken := createJWTToken(t, 10*time.Second)
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
