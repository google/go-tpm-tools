package util

import (
	"bytes"
	"context"
	"encoding/base64"
	"reflect"
	"testing"

	"cloud.google.com/go/compute/metadata"
	"github.com/containerd/containerd/namespaces"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm-tools/verifier"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func TestGetAttestation(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	tests := []struct {
		name       string
		keyFetcher TpmKeyFetcher
	}{
		{"RSA", client.AttestationKeyRSA},
		{"ECC", client.AttestationKeyECC},
	}
	for _, op := range tests {
		t.Run(op.name, func(t *testing.T) {
			attestation, err := GetAttestation(rwc, op.keyFetcher, []byte("test"))
			if err != nil {
				t.Errorf("Failed to get attestation %s", err)
			}
			if !bytes.Equal(attestation.EventLog, test.Rhel8EventLog) {
				t.Errorf("attestation event log mismatch %s", err)
			}
		})
	}
}

func TestGetRESTClient(t *testing.T) {
	ctx := namespaces.WithNamespace(context.Background(), namespaces.Default)

	mockOauth2Server, err := NewMockOauth2Server()
	if err != nil {
		t.Error(err)
	}
	defer mockOauth2Server.Stop()

	// Endpoint is Google's OAuth 2.0 default endpoint. Change to mock server.
	google.Endpoint = oauth2.Endpoint{
		AuthURL:   mockOauth2Server.Server.URL + "/o/oauth2/auth",
		TokenURL:  mockOauth2Server.Server.URL + "/token",
		AuthStyle: oauth2.AuthStyleInParams,
	}

	mockAttestationServer, err := NewMockAttestationServer()
	if err != nil {
		t.Error(err)
	}
	defer mockAttestationServer.Stop()

	restClient, err := GetRESTClient(ctx, mockAttestationServer.Server.URL, "test-project", "us-central")
	if err != nil {
		t.Errorf("Failed to create rest client %s", err)
	}
	gotChallenge, err := restClient.CreateChallenge(ctx)
	if err != nil {
		t.Errorf("Failed to call CreateChallenge %s", err)
	}
	gotTokenResponse, err := restClient.VerifyAttestation(ctx, verifier.VerifyAttestationRequest{
		Challenge:   gotChallenge,
		Attestation: &attest.Attestation{},
	})
	if err != nil {
		t.Errorf("Failed to call VerifyAttestation %s", err)
	}

	wantNonce, _ := base64.StdEncoding.DecodeString(FakeTpmNonce)
	wantChallenge := &verifier.Challenge{
		Name:   "projects/test-project/locations/us-central-1/challenges/" + FakeChallengeUUID,
		Nonce:  []byte(wantNonce),
		ConnID: ""}
	wantToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0IiwiaWF0IjoxNzA5NzUyNTI1LCJleHAiOjE5MTk3NTI1MjV9.EBLA2zX3c-Fu0l--J9Gey6LIXMO1TFRCoe3bzuPGc1k"
	if !reflect.DeepEqual(gotChallenge, wantChallenge) {
		t.Error("Challenge Mismatch")
	}
	if !bytes.Equal(gotTokenResponse.ClaimsToken, []byte(wantToken)) {
		t.Error("Token Mismatch")
	}

}

func TestGetRegion(t *testing.T) {
	var dummyMetaInstance = Instance{ProjectID: "test-project", ProjectNumber: "1922337278274", Zone: "us-central-1a", InstanceID: "12345678", InstanceName: "default"}
	mockMdsServer, err := NewMetadataServer(dummyMetaInstance)
	if err != nil {
		t.Error(err)
	}
	defer mockMdsServer.Stop()
	// Metadata Server (MDS). A GCP specific client.
	mdsClient := metadata.NewClient(nil)
	region, err := GetRegion(mdsClient)
	if err != nil {
		t.Errorf("Failed to GetRegion %s", err)
	}
	if region != "us-central" {
		t.Error("Region Mismatch")
	}
}
