package ita

import (
	"bytes"
	"context"
	"crypto/sha512"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/google/go-tpm-tools/verifier"
	"golang.org/x/exp/slices"
)

const (
	usBaseURL = "https://portal.trustauthority.intel.com"
	euBaseURL = "https://portal.eu.trustauthority.intel.com"

	apiURL = "https://api.trustauthority.intel.com"

	nonceEndpoint = "/appraisal/v2/nonce"
	tokenEndpoint = "/appraisal/v2/attest"

	apiKeyHeader      = "x-api-key"
	acceptHeader      = "Accept"
	contentTypeHeader = "Content-Type"
	applicationJSON   = "application/json"

	challengeNamePrefix = "ita://"
)

// Available regions https://cloud.google.com/compute/docs/regions-zones#available.
var euRegions []string = []string{
	"europe-north1",
	"europe-central2",
	"europe-southwest1",
	"europe-west1",
	"europe-west3",
	"europe-west4",
	"europe-west8",
	"europe-west9",
	"europe-west10",
	"europe-west12",
}

type client struct {
	inner   *http.Client
	baseURL string
	apiURL  string
	apiKey  string
}

func NewClient(ctx context.Context, apiKey string, region string) (verifier.Client, error) {
	baseURL := usBaseURL

	// If region is in the EU, use the appropriate base URL.
	if slices.Contains(euRegions, region) {
		baseURL = euBaseURL
	}

	return NewClientWithBaseURL(ctx, apiKey, baseURL)
}

func NewClientWithBaseURL(ctx context.Context, apiKey string, baseURL string) (verifier.Client, error) {
	if apiKey == "" {
		return nil, errors.New("API Key required to initialize ITA connector")
	}

	innerClient := &http.Client{
		Transport: &http.Transport{
			// TODO: See how this should be configured.
			TLSClientConfig: &tls.Config{},
			Proxy:           http.ProxyFromEnvironment,
		},
	}

	return &client{
		inner:   innerClient,
		baseURL: baseURL,
		apiURL:  apiURL,
		apiKey:  apiKey,
	}, nil
}

// Confirm that client implements verifier.Client interface.
var _ verifier.Client = (*client)(nil)

type itaNonce struct {
	Val       []byte `json:"val"`
	Iat       []byte `json:"iat"`
	Signature []byte `json:"signature"`
}

func (c *client) CreateChallenge(ctx context.Context) (*verifier.Challenge, error) {
	url := c.apiURL + nonceEndpoint

	headers := map[string]string{
		apiKeyHeader: c.apiKey,
		acceptHeader: applicationJSON,
	}

	var resp itaNonce
	if err := c.doHTTPRequest(http.MethodGet, url, nil, headers, &resp); err != nil {
		return nil, err
	}

	// The ITA evidence nonce is a concatenation+hash of Val and Iat. See references below:
	// https://github.com/intel/trustauthority-client-for-go/blob/main/go-connector/attest.go#L22
	// https://github.com/intel/trustauthority-client-for-go/blob/main/go-tdx/tdx_adapter.go#L37
	nonce := append(resp.Val, resp.Iat...)

	hash := sha512.New()
	_, err := hash.Write(nonce)
	if err != nil {
		return nil, fmt.Errorf("error hashing ITA nonce: %v", err)
	}
	// Do we have anything that needs to be in user data?
	// _, err = hash.Write(adapter.uData)

	return &verifier.Challenge{
		Name:  challengeNamePrefix + string(resp.Val),
		Nonce: hash.Sum(nil),
	}, nil
}

func (c *client) VerifyAttestation(ctx context.Context, request verifier.VerifyAttestationRequest) (*verifier.VerifyAttestationResponse, error) {
	tokenReq := tokenRequest{
		PolicyMatch: true,
		TDX: tdxEvidence{
			// Add EventLog field.
			CanonicalEventLog: request.TDCCELAttestation.CanonicalEventLog,
			Quote:             request.TDCCELAttestation.TdQuote,
		},
		SigAlg: "RS256", // Figure out what this should be.
		GCP: gcpData{
			AKCert:            request.TDCCELAttestation.AkCert,
			IntermediateCerts: request.TDCCELAttestation.IntermediateCerts,
			CSInfo: confidentialSpaceInfo{
				TokenOpts: tokenOptions{
					Audience:      request.TokenOptions.CustomAudience,
					Nonces:        request.TokenOptions.CustomNonce,
					TokenType:     request.TokenOptions.TokenType,
					TokenTypeOpts: tokenTypeOptions{},
				},
			},
		},
	}

	for _, token := range request.GcpCredentials {
		tokenReq.GCP.GcpCredentials = append(tokenReq.GCP.GcpCredentials, string(token))
	}

	for _, sig := range request.ContainerImageSignatures {
		itaSig := containerSignature{
			Payload:   sig.Payload,
			Signature: sig.Signature,
		}
		tokenReq.GCP.CSInfo.SignedEntities = append(tokenReq.GCP.CSInfo.SignedEntities, itaSig)
	}

	url := c.apiURL + tokenEndpoint
	headers := map[string]string{
		apiKeyHeader:      c.apiKey,
		acceptHeader:      applicationJSON,
		contentTypeHeader: applicationJSON,
	}

	var resp tokenResponse
	if err := c.doHTTPRequest(http.MethodPost, url, tokenReq, headers, &resp); err != nil {
		return nil, err
	}

	return &verifier.VerifyAttestationResponse{
		ClaimsToken: []byte(resp.Token),
	}, nil
}

func (c *client) doHTTPRequest(method string, url string, reqStruct any, headers map[string]string, respStruct any) error {
	// Create HTTP request.
	var reqBody *bytes.Reader = nil
	if reqStruct != nil {
		body, err := json.Marshal(reqStruct)
		if err != nil {
			return fmt.Errorf("error marshaling request: %v", err)
		}

		reqBody = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return fmt.Errorf("error creating HTTP request: %v", err)
	}

	// Add headers to request.
	for key, val := range headers {
		req.Header.Add(key, val)
	}

	resp, err := c.inner.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request error: %v", err)
	}

	// Read and unmarshal response body.
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response body: %v", err)
	}

	if err := json.Unmarshal(respBody, respStruct); err != nil {
		return fmt.Errorf("error unmarshaling response: %v", err)
	}

	return nil
}

// func (c *client) doHTTPRequest2(req *http.Request, headers map[string]string) ([]byte, error) {
// 	// Add headers to request.
// 	for key, val := range headers {
// 		req.Header.Add(key, val)
// 	}

// 	resp, err := c.inner.Do(req)
// 	if err != nil {
// 		return nil, fmt.Errorf("HTTP request error: %v", err)
// 	}

// 	// Read and return response body.
// 	body, err := io.ReadAll(resp.Body)
// 	if err != nil {
// 		return nil, fmt.Errorf("error reading response body: %v", err)
// 	}

// 	return body, nil
// }
