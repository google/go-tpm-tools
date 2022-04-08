package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/go-tpm-tools/cel"
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

	now := jwt.TimeFunc().Unix()
	claims := &jwt.StandardClaims{
		Id:        "test token",
		IssuedAt:  now,
		NotBefore: now,
		ExpiresAt: now + int64(ttl.Seconds()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(privkey)
	if err != nil {
		t.Fatalf("Error creating signed string: %v", err)
	}

	return []byte(signed)
}

func TestGetTTL(t *testing.T) {
	expectedTTL := 5 * time.Second
	token := createJWTToken(t, expectedTTL)

	ttl, err := getTTL(token)
	if err != nil {
		t.Fatalf("getTTL failed: %v", err)
	}

	// Expect TTL to be greater than 0 and no greater than the expected TTL.
	if ttl <= 0 {
		t.Errorf("expect TTL to be greater than 0, got %v", ttl)
	}

	if ttl > expectedTTL {
		t.Errorf("TTL exceeds the expected TTL: got %v, want no greater than %v", ttl, expectedTTL)
	}
}

func TestGetTTLError(t *testing.T) {
	_, err := getTTL([]byte("not a valid token"))
	if err == nil {
		t.Error("getTTL returned success, expected error.")
	}
}

func TestFetchAndWriteTokenSucceeds(t *testing.T) {
	ctx := context.Background()

	expectedToken := createJWTToken(t, 5*time.Second)

	runner := ContainerRunner{
		attestAgent: &fakeAttestationAgent{
			attestFunc: func(context.Context) ([]byte, error) {
				return expectedToken, nil
			},
		},
	}
	defer func() {
		if runner.tokenRefresher.timer != nil {
			// Drain the timer channel if expired.
			if !runner.tokenRefresher.timer.Stop() {
				<-runner.tokenRefresher.timer.C
			}

			runner.tokenRefresher.done <- true
		}
	}()

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
	ctx := context.Background()

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
	}
	defer func() {
		if runner.tokenRefresher.timer != nil {
			runner.tokenRefresher.timer.Stop()
			runner.tokenRefresher.done <- true
		}
	}()

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

func TestTokenRefresh(t *testing.T) {
	ctx := context.Background()

	expectedToken := createJWTToken(t, 5*time.Second)

	ttl := 5 * time.Second

	runner := ContainerRunner{
		attestAgent: &fakeAttestationAgent{
			attestFunc: func(context.Context) ([]byte, error) {
				return expectedToken, nil
			},
		},
	}
	defer func() {
		if runner.tokenRefresher.timer != nil {
			// Drain the timer channel if expired.
			if !runner.tokenRefresher.timer.Stop() {
				<-runner.tokenRefresher.timer.C
			}
			runner.tokenRefresher.done <- true
		}
	}()

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
