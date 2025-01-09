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
)

const (
	itaURL = "https://api.trustauthority.intel.com"

	nonceEndpoint = "/appraisal/v2/nonce"
	tokenEndpoint = "/appraisal/v2/attest"

	apiKeyHeader      = "x-api-key"
	acceptHeader      = "Accept"
	contentTypeHeader = "Content-Type"
	applicationJSON   = "application/json"

	challengeNamePrefix = "ita://"
)

type client struct {
	inner  *http.Client
	apiURL string
	apiKey string
}

func NewClient(apiKey string) (verifier.Client, error) {
	if apiKey == "" {
		return nil, errors.New("API Key required to initialize ITA connector")
	}

	return &client{
		inner: &http.Client{
			Transport: &http.Transport{
				// TODO: See how this should be configured.
				TLSClientConfig: &tls.Config{},
				Proxy:           http.ProxyFromEnvironment,
			},
		},
		apiURL: itaURL,
		apiKey: apiKey,
	}, nil
}

// Confirm that client implements verifier.Client interface.
var _ verifier.Client = (*client)(nil)

type itaNonce struct {
	Val       []byte `json:"val"`
	Iat       []byte `json:"iat"`
	Signature []byte `json:"signature"`
}

// The ITA evidence nonce is a concatenation+hash of Val and Iat. See references below:
// https://github.com/intel/trustauthority-client-for-go/blob/main/go-connector/attest.go#L22
// https://github.com/intel/trustauthority-client-for-go/blob/main/go-tdx/tdx_adapter.go#L37
func createHashedNonce(nonce *itaNonce) ([]byte, error) {
	hash := sha512.New()
	_, err := hash.Write(append(nonce.Val, nonce.Iat...))
	if err != nil {
		return nil, fmt.Errorf("error hashing ITA nonce: %v", err)
	}

	// Do we have anything that needs to be in user data?
	// _, err = hash.Write(adapter.uData)

	return hash.Sum(nil), err
}

func (c *client) CreateChallenge(_ context.Context) (*verifier.Challenge, error) {
	url := c.apiURL + nonceEndpoint

	headers := map[string]string{
		apiKeyHeader: c.apiKey,
		acceptHeader: applicationJSON,
	}

	resp := &itaNonce{}
	if err := c.doHTTPRequest(http.MethodGet, url, nil, headers, &resp); err != nil {
		return nil, err
	}

	nonce, err := createHashedNonce(resp)
	if err != nil {
		return nil, err
	}

	return &verifier.Challenge{
		Name:  challengeNamePrefix + string(resp.Val),
		Nonce: nonce,
	}, nil
}

func convertRequestToTokenRequest(request verifier.VerifyAttestationRequest) tokenRequest {
	tokenReq := tokenRequest{
		PolicyMatch: true,
		TDX: tdxEvidence{
			// Add EventLog field.
			EventLog:          request.TDCCELAttestation.CcelData,
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

	return tokenReq
}

func (c *client) VerifyAttestation(_ context.Context, request verifier.VerifyAttestationRequest) (*verifier.VerifyAttestationResponse, error) {
	tokenReq := convertRequestToTokenRequest(request)

	url := c.apiURL + tokenEndpoint
	headers := map[string]string{
		apiKeyHeader:      c.apiKey,
		acceptHeader:      applicationJSON,
		contentTypeHeader: applicationJSON,
	}

	resp := &tokenResponse{}
	if err := c.doHTTPRequest(http.MethodPost, url, tokenReq, headers, &resp); err != nil {
		return nil, err
	}

	return &verifier.VerifyAttestationResponse{
		ClaimsToken: []byte(resp.Token),
	}, nil
}

func (c *client) doHTTPRequest(method string, url string, reqStruct any, headers map[string]string, respStruct any) error {
	// Create HTTP request.
	var req *http.Request
	var err error
	if reqStruct != nil {
		body, err := json.Marshal(reqStruct)
		if err != nil {
			return fmt.Errorf("error marshaling request: %v", err)
		}

		req, err = http.NewRequest(method, url, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("error creating HTTP request: %v", err)
		}
	} else {
		req, err = http.NewRequest(method, url, nil)
		if err != nil {
			return fmt.Errorf("error creating HTTP request: %v", err)
		}
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
