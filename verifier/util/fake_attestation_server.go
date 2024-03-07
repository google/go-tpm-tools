package util

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/net/http2"
)

const fakeAsHostEnv = "GOOGLE_APPLICATION_CREDENTIALS"
const fakeChallengeUUID = "947b4f7b-e6d4-4cfe-971c-39ffe00268ba"
const fakeTpmNonce = "R29vZ0F0dGVzdFYxeGtJUGlRejFPOFRfTzg4QTRjdjRpQQ=="

// attestationServer provides fake implementation for the GCE attestation server.
type attestationServer struct {
	Server           *httptest.Server
	OldFakeAsHostEnv string
}

type fakeOidcTokenPayload struct {
	Audience  string `json:"aud"`
	IssuedAt  int64  `json:"iat"`
	ExpiredAt int64  `json:"exp"`
}

func (payload *fakeOidcTokenPayload) Valid() error {
	return nil
}

func NewMockAttestationServer() (*attestationServer, error) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		locationPath := "/v1/projects/test-project/locations/us-central"
		if r.URL.Path == locationPath {
			location := "{\n  \"name\": \"projects/test-project/locations/us-central-1\",\n  \"locationId\": \"us-central-1\"\n}\n"
			w.Write([]byte(location))
		}
		challengePath := locationPath + "-1/challenges"
		if r.URL.Path == challengePath {
			challenge := "{\n  \"name\": \"projects/test-project/locations/us-central-1/challenges/947b4f7b-e6d4-4cfe-971c-39ffe00268ba\",\n  \"createTime\": \"2023-09-21T01:04:48.230111757Z\",\n  \"expireTime\": \"2023-09-21T02:04:48.230111757Z\",\n  \"tpmNonce\": \"" + fakeTpmNonce + "\"\n}\n"
			w.Write([]byte(challenge))
		}
		challengeNonce := "/947b4f7b-e6d4-4cfe-971c-39ffe00268ba"
		verifyAttestationPath := challengePath + challengeNonce + ":verifyAttestation"
		if r.URL.Path == verifyAttestationPath {
			payload := &fakeOidcTokenPayload{
				Audience:  "test",
				IssuedAt:  1709752525,
				ExpiredAt: 1919752525,
			}
			jwtTokenUnsigned := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
			fakeJwtToken, err := jwtTokenUnsigned.SignedString([]byte("kcxjxnalpraetgccnnwhpnfwocxscaih"))
			if err != nil {
				fmt.Print("error creating test OIDC token")
			}
			w.Write([]byte("{\n  \"oidcClaimsToken\": \"" + fakeJwtToken + "\"\n}\n"))
		}
	})
	httpServer := httptest.NewUnstartedServer(handler)
	if err := http2.ConfigureServer(httpServer.Config, new(http2.Server)); err != nil {
		return nil, fmt.Errorf("failed to configure HTTP/2 server: %v", err)
	}
	httpServer.Start()

	// create test oauth2 credentials
	testCredentials := map[string]string{
		"client_id":     "id",
		"client_secret": "testdata",
		"refresh_token": "testdata",
		"type":          "authorized_user",
	}

	credentialsData, err := json.MarshalIndent(testCredentials, "", "  ") // Indent for readability
	if err != nil {
		return nil, err
	}

	file, err := os.Create("/tmp/test_credentials")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	_, err = file.Write(credentialsData)
	if err != nil {
		return nil, err
	}

	old := os.Getenv(fakeAsHostEnv)
	os.Setenv(fakeAsHostEnv, "/tmp/test_credentials")

	return &attestationServer{OldFakeAsHostEnv: old, Server: httpServer}, nil
}

// Stop shuts down the server.
func (s *attestationServer) Stop() {
	os.Remove("/tmp/test_credentials")
	os.Setenv(fakeAsHostEnv, s.OldFakeAsHostEnv)
	s.Server.Close()
}
