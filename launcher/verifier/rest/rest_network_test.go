package rest

import (
	"context"
	"log"
	"testing"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
	"github.com/google/go-tpm-tools/launcher/agent"
	"github.com/google/go-tpm-tools/launcher/internal/signaturediscovery"
	"github.com/google/go-tpm-tools/launcher/spec"
	"github.com/google/go-tpm-tools/launcher/verifier"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
)

var (
	fakeProject = "confidentialcomputing-e2e"
	fakeRegion  = "us-central1"
)

// Skip the test if we are not running in an environment with Google API
func testClient(t *testing.T) verifier.Client {
	// TODO: Connect to the autopush endpoint by default.
	hClient, err := google.DefaultClient(context.Background())
	if err != nil {
		t.Skipf("Getting HTTP Client: %v", err)
	}

	vClient, err := NewClient(context.Background(),
		fakeProject,
		fakeRegion,
		option.WithHTTPClient(hClient),
	)
	if err != nil {
		t.Fatalf("Creating Verifier Client: %v", err)
	}
	return vClient
}

func testPrincipalIDTokenFetcher(_ string) ([][]byte, error) {
	return [][]byte{}, nil
}

func TestWithAgent(t *testing.T) {
	vClient := testClient(t)

	tpm := test.GetTPM(t)
	defer client.CheckedClose(t, tpm)

	agent := agent.CreateAttestationAgent(tpm, client.AttestationKeyECC, vClient, testPrincipalIDTokenFetcher, signaturediscovery.NewFakeClient(), spec.LaunchSpec{}, log.Default())
	token, err := agent.Attest(context.Background())
	if err != nil {
		t.Errorf("failed to attest to Attestation Service: %v", err)
	}
	t.Logf("Got Token: |%v|", string(token))
}
