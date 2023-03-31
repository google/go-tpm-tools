package agent

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
	"github.com/google/go-tpm-tools/launcher/verifier/fake"
)

func TestAttest(t *testing.T) {
	tpm := test.GetTPM(t)
	defer client.CheckedClose(t, tpm)

	fakeSigner, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Errorf("Failed to generate signing key %v", err)
	}
	verifierClient := fake.NewClient(fakeSigner)
	agent := CreateAttestationAgent(tpm, client.AttestationKeyECC, verifierClient, placeholderFetcher)

	tokenBytes, err := agent.Attest(context.Background())
	if err != nil {
		t.Errorf("failed to attest to Attestation Service: %v", err)
	}

	registeredClaims := &jwt.RegisteredClaims{}
	keyFunc := func(token *jwt.Token) (interface{}, error) { return fakeSigner.Public(), nil }
	token, err := jwt.ParseWithClaims(string(tokenBytes), registeredClaims, keyFunc)
	if err != nil {
		t.Errorf("Failed to parse token %s", err)
	}

	if err = registeredClaims.Valid(); err != nil {
		t.Errorf("Invalid exp, iat, or nbf: %s", err)
	}

	if !registeredClaims.VerifyAudience("https://sts.googleapis.com/", true) {
		t.Errorf("Invalid aud")
	}

	if !registeredClaims.VerifyIssuer("https://confidentialcomputing.googleapis.com/", true) {
		t.Errorf("Invalid iss")
	}

	if registeredClaims.Subject != "https://www.googleapis.com/compute/v1/projects/fakeProject/zones/fakeZone/instances/fakeInstance" {
		t.Errorf("Invalid sub")
	}

	fmt.Printf("token.Claims: %v\n", token.Claims)
}

func placeholderFetcher(_ string) ([][]byte, error) {
	return [][]byte{}, nil
}
