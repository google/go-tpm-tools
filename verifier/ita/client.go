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
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/google/go-tpm-tools/verifier"
)

const (
	nonceEndpoint = "/appraisal/v2/nonce"
	tokenEndpoint = "/appraisal/v2/attest/gcp/confidentialspace"

	apiKeyHeader      = "x-api-key"
	acceptHeader      = "Accept"
	contentTypeHeader = "Content-Type"
	applicationJSON   = "application/json"

	challengeNamePrefix = "ita://"

	serialConsoleFile = "/dev/console"
)

var regionalURLs map[string]string = map[string]string{
	"US": "https://api.trustauthority.intel.com",
	"EU": "https://api.eu.trustauthority.intel.com",
}

type itaClient struct {
	inner  *http.Client
	apiURL string
	apiKey string
	logger *slog.Logger
}

func urlFromRegion(region string) (string, error) {
	if region == "" {
		return "", errors.New("API region required to initialize ITA client")
	}
	url, ok := regionalURLs[strings.ToUpper(region)]
	if !ok {
		// Create list of allowed regions.
		keys := []string{}
		for k := range regionalURLs {
			keys = append(keys, k)
		}
		return "", fmt.Errorf("unsupported region %v, expect one of %v", region, keys)
	}

	return url, nil
}

// Confirm that client implements verifier.Client interface.
var _ verifier.Client = (*itaClient)(nil)

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

	return hash.Sum(nil), err
}

func NewClient(itaConfig verifier.ITAConfig) (verifier.Client, error) { //region string, key string) (verifier.Client, error) {
	// TODO - these clients should be able to accept a logger as they are only used in the launcher.
	// Remove this when they get access to the launcher/internal logger.
	// This is less than ideal to say the least.
	serialConsole, err := os.OpenFile(serialConsoleFile, os.O_WRONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open serial console for writing: %v", err)
	}

	slg := slog.New(slog.NewTextHandler(serialConsole, nil))
	slg.Info("Serial Console logger initialized")

	// This is necessary for DEBUG logs to propagate properly.
	slog.SetDefault(slg)

	url, err := urlFromRegion(itaConfig.ITARegion)
	if err != nil {
		return nil, err
	}

	return &itaClient{
		inner: &http.Client{
			Transport: &http.Transport{
				// https://github.com/intel/trustauthority-client-for-go/blob/main/go-connector/token.go#L130.
				TLSClientConfig: &tls.Config{
					CipherSuites: []uint16{
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					},
					InsecureSkipVerify: false,
					MinVersion:         tls.VersionTLS12,
				},
				Proxy: http.ProxyFromEnvironment,
			},
		},
		apiURL: url,
		apiKey: itaConfig.ITAKey,
		logger: slg,
	}, nil
}

func (c *itaClient) CreateChallenge(_ context.Context) (*verifier.Challenge, error) {
	url := c.apiURL + nonceEndpoint
	c.logger.Info("Calling ITA create challenge", "url", url)

	headers := map[string]string{
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
		Name:      challengeNamePrefix + string(resp.Val),
		Nonce:     nonce,
		Val:       resp.Val,
		Iat:       resp.Iat,
		Signature: resp.Signature,
	}, nil
}

func (c *itaClient) VerifyAttestation(_ context.Context, request verifier.VerifyAttestationRequest) (*verifier.VerifyAttestationResponse, error) {
	if request.TDCCELAttestation == nil {
		return nil, errors.New("TDX required for ITA attestation")
	}

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

func (c *itaClient) doHTTPRequest(method string, url string, reqStruct any, headers map[string]string, respStruct any) error {
	// Create HTTP request.
	var req *http.Request
	var err error
	logBody := ""
	if reqStruct != nil {
		body, err := json.Marshal(reqStruct)
		logBody = string(body)
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
	headers[apiKeyHeader] = string(c.apiKey)
	for key, val := range headers {
		req.Header.Add(key, val)
	}

	c.logger.Info("API request details", "url", url, "method", method, "headers", headers, "body", logBody)

	resp, err := c.inner.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request error: %v", err)
	}
	defer resp.Body.Close()

	// Read and unmarshal response body.
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response body: %v", err)
	}
	c.logger.Info("resp", "code", resp.StatusCode, "body", respBody)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP request failed with status code %d, response body %s", resp.StatusCode, string(respBody))
	}

	if err := json.Unmarshal(respBody, respStruct); err != nil {
		return fmt.Errorf("error unmarshaling response: %v", err)
	}

	return nil
}

func convertRequestToTokenRequest(request verifier.VerifyAttestationRequest) tokenRequest {
	// Trim trailing 0xFF bytes from CCEL Data.
	data := request.TDCCELAttestation.CcelData
	trimIndex := len(data)

	for ; trimIndex >= 0; trimIndex-- {
		c := data[trimIndex-1]
		// Proceed until 0xFF padding ends.
		if c != byte(255) {
			break
		}
	}

	tokenReq := tokenRequest{
		PolicyMatch: true,
		TDX: tdxEvidence{
			EventLog:          data[:trimIndex],
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
			AKCert:            request.TDCCELAttestation.AkCert,
			IntermediateCerts: request.TDCCELAttestation.IntermediateCerts,
			CSInfo: confidentialSpaceInfo{
				TokenOpts: tokenOptions{},
			},
		},
	}

	if request.TokenOptions != nil {
		tokenReq.GCP.CSInfo.TokenOpts = tokenOptions{
			Audience:      request.TokenOptions.Audience,
			Nonces:        request.TokenOptions.Nonces,
			TokenType:     request.TokenOptions.TokenType,
			TokenTypeOpts: tokenTypeOptions{},
		}
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

func (c *itaClient) VerifyConfidentialSpace(ctx context.Context, request verifier.VerifyAttestationRequest) (*verifier.VerifyAttestationResponse, error) {
	return c.VerifyAttestation(ctx, request)
}
