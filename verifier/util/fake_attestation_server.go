package util

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"

	"cloud.google.com/go/confidentialcomputing/apiv1/confidentialcomputingpb"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/net/http2"
	"google.golang.org/protobuf/encoding/protojson"
)

// FakeChallengeUUID is the challenge for fake attestation server
const FakeChallengeUUID = "947b4f7b-e6d4-4cfe-971c-39ffe00268ba"

// FakeTpmNonce is the tpm nonce for fake attestation server
const FakeTpmNonce = "R29vZ0F0dGVzdFYxeGtJUGlRejFPOFRfTzg4QTRjdjRpQQ=="

// FakeCustomNonce is the custom nonce for fake attestation server
var FakeCustomNonce = []string{"1234567890", "1234567890"}

// FakeCustomNonce is the custom audience for fake attestation server
const FakeCustomAudience = "https://api.test.com"

// MockAttestationServer provides fake implementation for the GCE attestation server.
type MockAttestationServer struct {
	Server *httptest.Server
}

type fakeOidcTokenPayload struct {
	Audience  string `json:"aud"`
	IssuedAt  int64  `json:"iat"`
	ExpiredAt int64  `json:"exp"`
}

func (payload *fakeOidcTokenPayload) Valid() error {
	return nil
}

// NewMockAttestationServer creates a mock verifier
func NewMockAttestationServer() (*MockAttestationServer, error) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		locationPath := "/v1/projects/test-project/locations/us-central"
		if r.URL.Path == locationPath {
			location := "{\n  \"name\": \"projects/test-project/locations/us-central-1\",\n  \"locationId\": \"us-central-1\"\n}\n"
			w.Write([]byte(location))
		}
		challengePath := locationPath + "-1/challenges"
		if r.URL.Path == challengePath {
			challenge := "{\n  \"name\": \"projects/test-project/locations/us-central-1/challenges/" + FakeChallengeUUID + "\",\n  \"createTime\": \"2023-09-21T01:04:48.230111757Z\",\n  \"expireTime\": \"2023-09-21T02:04:48.230111757Z\",\n  \"tpmNonce\": \"" + FakeTpmNonce + "\"\n}\n"
			w.Write([]byte(challenge))
		}
		verifyAttestationPath := challengePath + "/" + FakeChallengeUUID + ":verifyAttestation"
		if r.URL.Path == verifyAttestationPath {
			err := validateCustomNonceAndAudienceFromRequest(r)
			if err != nil {
				fmt.Print("error validating Custom Nonce and Custom Audience")
				http.Error(w, "Invalid Nonce or Audience", http.StatusBadRequest) // Return 400 Bad Request
				return
			}
			payload := &fakeOidcTokenPayload{
				Audience:  "test",
				IssuedAt:  1709752525,
				ExpiredAt: 1919752525,
			}
			jwtTokenUnsigned := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
			fakeJwtToken, err := jwtTokenUnsigned.SignedString([]byte("kcxjxnalpraetgccnnwhpnfwocxscaih"))
			if err != nil {
				fmt.Print("error creating test OIDC token")
				http.Error(w, "Invalid OIDC token creation", http.StatusBadRequest) // Return 400 Bad Request
				return
			}
			w.Write([]byte("{\n  \"oidcClaimsToken\": \"" + fakeJwtToken + "\"\n}\n"))
		}
	})
	httpServer := httptest.NewUnstartedServer(handler)
	if err := http2.ConfigureServer(httpServer.Config, new(http2.Server)); err != nil {
		return nil, fmt.Errorf("failed to configure HTTP/2 server: %v", err)
	}
	httpServer.Start()

	return &MockAttestationServer{Server: httpServer}, nil
}

// Stop shuts down the server.
func (s *MockAttestationServer) Stop() {
	s.Server.Close()

}

// validateCustomNonceAndAudienceFromRequest validates the custom nonce and custom audience from a VerifyAttestationRequest.
func validateCustomNonceAndAudienceFromRequest(r *http.Request) error {
	req := &confidentialcomputingpb.VerifyAttestationRequest{}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("error reading request body: %v", err)
	}
	defer r.Body.Close()

	if err := protojson.Unmarshal(body, req); err != nil {
		return fmt.Errorf("error decoding attestation request: %v", err)
	}

	if req.TokenOptions.Nonce != nil {
		if req.TokenOptions.Nonce[0] != FakeCustomNonce[0] || req.TokenOptions.Nonce[1] != FakeCustomNonce[1] {
			return fmt.Errorf("error comparing custom nonce: %v", err)
		}
	}
	if req.TokenOptions.Audience != "" {
		if req.TokenOptions.Audience != FakeCustomAudience {
			return fmt.Errorf("error comparing custom audience: %v", err)
		}
	}
	return nil
}
