package internal_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"reflect"
	"testing"

	"github.com/containerd/containerd/namespaces"
	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm-tools/verifier"
	"github.com/google/go-tpm-tools/verifier/util"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func TestNewRESTClient(t *testing.T) {
	ctx := namespaces.WithNamespace(context.Background(), namespaces.Default)

	mockOauth2Server, err := util.NewMockOauth2Server()
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

	mockAttestationServer, err := util.NewMockAttestationServer()
	if err != nil {
		t.Error(err)
	}
	defer mockAttestationServer.Stop()

	restClient, err := util.NewRESTClient(ctx, mockAttestationServer.Server.URL, "test-project", "us-central")
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

	wantNonce, _ := base64.StdEncoding.DecodeString(util.FakeTpmNonce)
	wantChallenge := &verifier.Challenge{
		Name:   "projects/test-project/locations/us-central-1/challenges/" + util.FakeChallengeUUID,
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
