package ita

import (
	"context"
	"crypto/sha512"
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/google/go-tpm-tools/verifier"
	itaconnector "github.com/intel/trustauthority-client/go-connector/connector"
	"golang.org/x/exp/slices"
)

const (
	usBaseURL = "https://portal.trustauthority.intel.com"
	euBaseURL = "https://portal.eu.trustauthority.intel.com"

	namePrefix = "ita://"
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
	cfg := &itaconnector.Config{
		BaseURL: baseURL,
		ApiUrl:  "https://api.trustauthority.intel.com",
		TlsCfg:  &tls.Config{},
		ApiKey:  apiKey,
		RClient: &itaconnector.RetryConfig{},
	}

	connector, err := itaconnector.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("error creating ITA connector: %v, err")
	}

	return &client{connector}, nil
}

type client struct {
	connector itaconnector.Connector
}

// Confirm that client implements verifier.Client interface.
var connector verifier.Client = (*client)(nil)

func (c *client) CreateChallenge(ctx context.Context) (*verifier.Challenge, error) {
	resp, err := c.connector.GetNonce(itaconnector.GetNonceArgs{})
	if err != nil {
		return nil, fmt.Errorf("GetNonce error: %v", err)
	}

	// The ITA evidence nonce is a concatenation+hash of Val and Iat. See references below:
	// https://github.com/intel/trustauthority-client-for-go/blob/main/go-connector/attest.go#L22
	// https://github.com/intel/trustauthority-client-for-go/blob/main/go-tdx/tdx_adapter.go#L37
	nonce := append(resp.Val, resp.Iat...)

	hash := sha512.New()
	_, err = hash.Write(nonce)
	if err != nil {
		return nil, fmt.Errorf("error hashing ITA nonce: %v", err)
	}
	// Do we have anything that needs to be in user data?
	// _, err = hash.Write(adapter.uData)

	return &verifier.Challenge{
		Name:      namePrefix + string(resp.Val),
		Nonce:     hash.Sum(nil),
		Val:       resp.Val,
		Iat:       resp.Iat,
		Signature: resp.Signature,
	}, nil
}

func (c *client) VerifyAttestation(ctx context.Context, request verifier.VerifyAttestationRequest) (*verifier.VerifyAttestationResponse, error) {
	req := itaconnector.GetTokenArgs{
		Nonce: &itaconnector.VerifierNonce{
			Val:       request.Challenge.Val,
			Iat:       request.Challenge.Iat,
			Signature: request.Challenge.Signature,
		},
		Evidence: &itaconnector.Evidence{},
	}

	// TODO: Replace with Confidential Space endpoint.
	resp, err := c.connector.GetToken(req)
	if err != nil {
		return nil, fmt.Errorf("GetToken error: %v", err)
	}

	return &verifier.VerifyAttestationResponse{
		ClaimsToken: []byte(resp.Token),
	}, nil
}
