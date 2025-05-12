package ita

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-tpm-tools/verifier"
	"github.com/google/go-tpm-tools/verifier/models"
)

var testVerifierRequest = verifier.VerifyAttestationRequest{
	GcpCredentials: [][]byte{
		[]byte("test-token1"),
		[]byte("test-token2"),
	},
	ContainerImageSignatures: []*verifier.ContainerSignature{
		{
			Payload:   []byte("test-payload1"),
			Signature: []byte("test-signature1"),
		},
		{
			Payload:   []byte("test-payload2"),
			Signature: []byte("test-signature2"),
		},
	},
	TDCCELAttestation: &verifier.TDCCELAttestation{
		CcelData:          []byte("test-ccelData"),
		CanonicalEventLog: []byte("test-cel"),
		TdQuote:           []byte("test-quote"),
		AkCert:            []byte("test-akcert"),
		IntermediateCerts: [][]byte{
			[]byte("test-intermediate1"),
			[]byte("test-intermediate2"),
		},
	},
	Challenge: &verifier.Challenge{
		Val:       []byte("test-nonce-val"),
		Iat:       []byte("123456"),
		Signature: []byte("test-nonce-sig"),
	},
	TokenOptions: &models.TokenOptions{
		Audience:  "testaud",
		Nonces:    []string{"testnonces"},
		TokenType: "testtokentype",
	},
}

func validateHTTPRequest(t *testing.T, r *http.Request, expectedMethod string, expectedHeaders map[string]string, expectedPath string) {
	// Verify HTTP Method.
	if r.Method != expectedMethod {
		t.Errorf("HTTP request does not have expected method: got %v, want %v", r.Method, http.MethodGet)
	}

	// Verify HTTP headers.
	for key, val := range expectedHeaders {
		if r.Header.Get(key) != val {
			t.Errorf("HTTP request does not have expected Content-Type header: got %s, want %s", r.Header.Get(key), val)
		}
	}

	// Verify requested path.
	if expectedPath != "" && r.URL.Path != expectedPath {
		t.Errorf("HTTP request does not have expected endpoint: got %v, want %v", r.URL.Path, nonceEndpoint)
	}
}

func TestCreateChallenge(t *testing.T) {
	testNonce := &itaNonce{
		Val:       []byte("test-val"),
		Iat:       []byte("test-iat"),
		Signature: []byte("test-signature"),
	}

	expectedNonce, err := createHashedNonce(testNonce)
	if err != nil {
		t.Fatalf("Unable to create expected nonce: %v", err)
	}

	expectedAPIKey := "test-api-key"
	expectedHeaders := map[string]string{
		apiKeyHeader: expectedAPIKey,
		acceptHeader: applicationJSON,
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		validateHTTPRequest(t, r, http.MethodGet, expectedHeaders, nonceEndpoint)

		// Send HTTP Response.
		marshaled, err := json.Marshal(testNonce)
		if err != nil {
			t.Fatalf("Unable to marshal server response: %s", testNonce)
		}

		w.Write(marshaled)
	}))

	itaClient := &client{
		inner:  http.DefaultClient,
		apiURL: ts.URL,
		apiKey: expectedAPIKey,
		logger: slog.Default(),
	}

	challenge, err := itaClient.CreateChallenge(context.Background())
	if err != nil {
		t.Fatalf("CreateChallenge() returned error: %v", err)
	}

	expectedChallenge := &verifier.Challenge{
		Name:      challengeNamePrefix + string(testNonce.Val),
		Nonce:     expectedNonce,
		Val:       testNonce.Val,
		Iat:       testNonce.Iat,
		Signature: testNonce.Signature,
	}

	if diff := cmp.Diff(*challenge, *expectedChallenge); diff != "" {
		t.Errorf("CreateChallenge() did not return the expected challenge: %v", diff)
	}
}

func TestVerifyAttestation(t *testing.T) {
	expectedReq := convertRequestToTokenRequest(testVerifierRequest)

	expectedResp := &verifier.VerifyAttestationResponse{
		ClaimsToken: []byte("test-ita-token"),
	}

	expectedAPIKey := "test-api-key"
	expectedHeaders := map[string]string{
		apiKeyHeader:      expectedAPIKey,
		acceptHeader:      applicationJSON,
		contentTypeHeader: applicationJSON,
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		validateHTTPRequest(t, r, http.MethodPost, expectedHeaders, tokenEndpoint)

		// Verify HTTP Request body.
		defer r.Body.Close()
		reqBody, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("Error reading HTTP request body: %s", err)
		}

		req := tokenRequest{}
		if err = json.Unmarshal(reqBody, &req); err != nil {
			t.Fatalf("Error unmarshaling HTTP request body: %s", err)
		}

		if diff := cmp.Diff(req, expectedReq); diff != "" {
			t.Errorf("Incorrect request recieved by server: %v", diff)
		}

		// Send HTTP Response.
		resp := tokenResponse{
			Token: string(expectedResp.ClaimsToken),
		}
		marshaled, err := json.Marshal(resp)
		if err != nil {
			t.Fatalf("Unable to marshal server response: %s", expectedResp)
		}

		w.Write(marshaled)
	}))

	itaClient := &client{
		inner:  http.DefaultClient,
		apiURL: ts.URL,
		apiKey: expectedAPIKey,
		logger: slog.Default(),
	}

	verifyResp, err := itaClient.VerifyAttestation(context.Background(), testVerifierRequest)
	if err != nil {
		t.Fatalf("VerifyAttestation() returned error: %v", err)
	}

	if diff := cmp.Diff(verifyResp, expectedResp); diff != "" {
		t.Errorf("VerifyAttestation did not return expected response: %v", diff)
	}
}

func TestDoHTTPRequest(t *testing.T) {
	expectedHeaders := map[string]string{
		apiKeyHeader: "testAPIKey",
		acceptHeader: applicationJSON,
	}

	expectedMethod := http.MethodPost
	expectedReq := tokenRequest{
		PolicyMatch: true,
		SigAlg:      "testsigalg",
		TDX: tdxEvidence{
			EventLog:          []byte("test event log"),
			CanonicalEventLog: []byte("test CEL"),
			Quote:             []byte("test quote"),
		},
	}

	expectedResp := tokenResponse{
		Token: "test-token",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		validateHTTPRequest(t, r, expectedMethod, expectedHeaders, "")

		// Verify HTTP Request body.
		defer r.Body.Close()
		reqBody, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("Error reading HTTP request body: %s", err)
		}

		req := tokenRequest{}
		if err = json.Unmarshal(reqBody, &req); err != nil {
			t.Fatalf("Error unmarshaling HTTP request body: %s", err)
		}

		if diff := cmp.Diff(req, expectedReq); diff != "" {
			t.Errorf("Incorrect request recieved by server: %v", diff)
		}

		// Send HTTP Response.
		marshaled, err := json.Marshal(expectedResp)
		if err != nil {
			t.Fatalf("Unable to marshal server response: %s", expectedResp)
		}

		w.Write(marshaled)
	}))

	itaClient := client{
		inner:  http.DefaultClient,
		logger: slog.Default(),
	}

	resp := &tokenResponse{}
	if err := itaClient.doHTTPRequest(expectedMethod, ts.URL, expectedReq, expectedHeaders, resp); err != nil {
		t.Fatalf("doHTTPRequest returned error: %v", err)
	}

	if diff := cmp.Diff(*resp, expectedResp); diff != "" {
		t.Errorf("doHTTPRequest did not return expected response: %v", diff)
	}
}

func TestConvertRequestToTokenRequest(t *testing.T) {
	expectedRequest := tokenRequest{
		PolicyMatch: true,
		TDX: tdxEvidence{
			// Add EventLog field.
			EventLog:          testVerifierRequest.TDCCELAttestation.CcelData,
			CanonicalEventLog: testVerifierRequest.TDCCELAttestation.CanonicalEventLog,
			Quote:             testVerifierRequest.TDCCELAttestation.TdQuote,
			VerifierNonce: nonce{
				Val:       testVerifierRequest.Challenge.Val,
				Iat:       testVerifierRequest.Challenge.Iat,
				Signature: testVerifierRequest.Challenge.Signature,
			},
		},
		SigAlg: "RS256", // Figure out what this should be.
		GCP: gcpData{
			GcpCredentials: []string{
				string(testVerifierRequest.GcpCredentials[0]),
				string(testVerifierRequest.GcpCredentials[1]),
			},
			AKCert:            testVerifierRequest.TDCCELAttestation.AkCert,
			IntermediateCerts: testVerifierRequest.TDCCELAttestation.IntermediateCerts,
			CSInfo: confidentialSpaceInfo{
				SignedEntities: []containerSignature{
					{
						Payload:   testVerifierRequest.ContainerImageSignatures[0].Payload,
						Signature: testVerifierRequest.ContainerImageSignatures[0].Signature,
					},
					{
						Payload:   testVerifierRequest.ContainerImageSignatures[1].Payload,
						Signature: testVerifierRequest.ContainerImageSignatures[1].Signature,
					},
				},
				TokenOpts: tokenOptions{
					Audience:      testVerifierRequest.TokenOptions.Audience,
					Nonces:        testVerifierRequest.TokenOptions.Nonces,
					TokenType:     testVerifierRequest.TokenOptions.TokenType,
					TokenTypeOpts: tokenTypeOptions{},
				},
			},
		},
	}

	convertedReq := convertRequestToTokenRequest(testVerifierRequest)

	if diff := cmp.Diff(convertedReq, expectedRequest); diff != "" {
		t.Errorf("convertRequestToTokenRequest did not return expected tokenRequest: %v", diff)
	}
}

func TestConvertRequestToTokenRequestWithCCELDataPadding(t *testing.T) {
	padding := bytes.Repeat([]byte{255}, 20)

	request := verifier.VerifyAttestationRequest{
		TDCCELAttestation: &verifier.TDCCELAttestation{
			CcelData:          append(testVerifierRequest.TDCCELAttestation.CcelData, padding...),
			CanonicalEventLog: []byte("test-cel"),
			TdQuote:           []byte("test-quote"),
			AkCert:            []byte("test-akcert"),
			IntermediateCerts: [][]byte{
				[]byte("test-intermediate1"),
				[]byte("test-intermediate2"),
			},
		},
		Challenge: testVerifierRequest.Challenge,
	}

	expectedRequest := tokenRequest{
		PolicyMatch: true,
		TDX: tdxEvidence{
			// Expect padding to be stripped in converted request.
			EventLog:          testVerifierRequest.TDCCELAttestation.CcelData,
			CanonicalEventLog: request.TDCCELAttestation.CanonicalEventLog,
			Quote:             request.TDCCELAttestation.TdQuote,
			VerifierNonce: nonce{
				Val:       request.Challenge.Val,
				Iat:       request.Challenge.Iat,
				Signature: request.Challenge.Signature,
			},
		},
		SigAlg: "RS256", // Figure out what this should be.
		GCP: gcpData{
			AKCert:            testVerifierRequest.TDCCELAttestation.AkCert,
			IntermediateCerts: testVerifierRequest.TDCCELAttestation.IntermediateCerts,
		},
	}

	convertedReq := convertRequestToTokenRequest(request)

	if diff := cmp.Diff(convertedReq, expectedRequest); diff != "" {
		t.Errorf("convertRequestToTokenRequest did not return expected tokenRequest: %v", diff)
	}
}

func TestURLFromRegion(t *testing.T) {
	for region, expectedURL := range regionalURLs {
		t.Run(region+" region", func(t *testing.T) {
			url, err := urlFromRegion(region)
			if err != nil {
				t.Fatalf("urlAndKey returned error: %v", err)
			}

			if url != expectedURL {
				t.Errorf("urlAndKey did not return expected URL: got %v, want %v", url, expectedURL)
			}
		})
	}
}

func TestURLFromRegionError(t *testing.T) {
	testcases := []struct {
		name           string
		region         string
		expectedSubstr string
	}{
		{
			name:           "Unsupported region",
			region:         "ANTARCTICA",
			expectedSubstr: "unsupported region",
		},
		{
			name:           "Empty input",
			region:         "",
			expectedSubstr: "region required",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := urlFromRegion(tc.region)
			if err == nil {
				t.Fatal("urlAndKey returned successfully, expected error")
			}

			if !strings.Contains(err.Error(), tc.expectedSubstr) {
				t.Errorf("urlAndKey did not return expected error: got %v, want %v", err.Error(), tc.expectedSubstr)
			}
		})
	}
}
