package ita

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-tpm-tools/verifier"
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
	}

	challenge, err := itaClient.CreateChallenge(context.Background())
	if err != nil {
		t.Fatalf("CreateChallenge() returned error: %v", err)
	}

	expectedChallenge := &verifier.Challenge{
		Name:  challengeNamePrefix + string(testNonce.Val),
		Nonce: expectedNonce,
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
		inner: http.DefaultClient,
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
					Audience:      testVerifierRequest.TokenOptions.CustomAudience,
					Nonces:        testVerifierRequest.TokenOptions.CustomNonce,
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
