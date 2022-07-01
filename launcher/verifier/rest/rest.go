// Package rest contains the code to use the REST-based Google API
package rest

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/go-tpm-tools/launcher/verifier"

	v1alpha1 "google.golang.org/api/confidentialcomputing/v1alpha1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

// NewClient creates a new REST client which is configured to perform
// attestations in a particular project and region.
func NewClient(ctx context.Context, projectID string, region string, opts ...option.ClientOption) (verifier.Client, error) {
	service, err := v1alpha1.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("can't create ConfidentialComputing v1alpha1 API client: %w", err)
	}

	projectName := fmt.Sprintf("projects/%s", projectID)
	locationName := fmt.Sprintf("%s/locations/%v", projectName, region)

	location, err := service.Projects.Locations.Get(locationName).Do()
	if err == nil {
		return &restClient{service, location}, nil
	}

	// Check if the error was due to a bad region name
	if apiErr, ok := err.(*googleapi.Error); ok && apiErr.Code == 403 {
		// In this case, inform the user about the allowed regions
		if list, listErr := service.Projects.Locations.List(projectName).Do(); listErr == nil {
			locations := make([]string, len(list.Locations))
			for i, loc := range list.Locations {
				locations[i] = loc.LocationId
			}
			return nil, fmt.Errorf(
				"unable to find region %q, available regions are [%s]: %w",
				region, strings.Join(locations, ", "), err,
			)
		}
	}

	return nil, fmt.Errorf("unable to use project %q and region %q: %w", projectID, region, err)
}

type restClient struct {
	service  *v1alpha1.Service
	location *v1alpha1.Location
}

// CreateChallenge implements verifier.Client
func (c *restClient) CreateChallenge(ctx context.Context) (*verifier.Challenge, error) {
	// Pass an empty Challenge for the input (all params are output-only)
	chal, err := c.service.Projects.Locations.Challenges.Create(
		c.location.Name,
		&v1alpha1.Challenge{},
	).Do()
	if err != nil {
		return nil, fmt.Errorf("calling v1alpha1.CreateChallenge: %w", err)
	}
	return convertChallengeFromREST(chal)
}

// VerifyAttestation implements verifier.Client
func (c *restClient) VerifyAttestation(ctx context.Context, request verifier.VerifyAttestationRequest) (*verifier.VerifyAttestationResponse, error) {
	response, err := c.service.Projects.Locations.Challenges.VerifyAttestation(
		request.Challenge.Name,
		convertRequestToREST(request),
	).Do()
	if err != nil {
		return nil, fmt.Errorf("calling v1alpha1.VerifyAttestation: %w", err)
	}
	return convertResponseFromREST(response)
}

var encoding = base64.StdEncoding

func convertChallengeFromREST(chal *v1alpha1.Challenge) (*verifier.Challenge, error) {
	nonce, err := encoding.DecodeString(chal.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Challenge.Nonce: %w", err)
	}
	return &verifier.Challenge{
		Name:  chal.Name,
		Nonce: nonce,
	}, nil
}

func convertRequestToREST(request verifier.VerifyAttestationRequest) *v1alpha1.VerifyAttestationRequest {
	idTokens := make([]string, len(request.GcpCredentials))
	for i, token := range request.GcpCredentials {
		idTokens[i] = encoding.EncodeToString(token)
	}

	quotes := make([]*v1alpha1.Quote, len(request.Attestation.GetQuotes()))
	for i, quote := range request.Attestation.GetQuotes() {
		pcrVals := map[string]string{}
		for idx, val := range quote.GetPcrs().GetPcrs() {
			strIdx := strconv.FormatUint(uint64(idx), 10)
			pcrVals[strIdx] = encoding.EncodeToString(val)
		}

		quotes[i] = &v1alpha1.Quote{
			RawQuote:     encoding.EncodeToString(quote.GetQuote()),
			RawSignature: encoding.EncodeToString(quote.GetRawSig()),
			HashAlgo:     int64(quote.GetPcrs().GetHash()),
			PcrValues:    pcrVals,
		}
	}

	certs := make([]string, len(request.Attestation.GetIntermediateCerts()))
	for i, cert := range request.Attestation.GetIntermediateCerts() {
		certs[i] = encoding.EncodeToString(cert)
	}

	return &v1alpha1.VerifyAttestationRequest{
		GcpCredentials: &v1alpha1.GcpCredentials{
			IdTokens: idTokens,
		},
		TpmAttestation: &v1alpha1.TpmAttestation{
			Quotes:            quotes,
			TcgEventLog:       encoding.EncodeToString(request.Attestation.GetEventLog()),
			CanonicalEventLog: encoding.EncodeToString(request.Attestation.GetCanonicalEventLog()),
			AkCert:            encoding.EncodeToString(request.Attestation.GetAkCert()),
			CertChain:         certs,
		},
	}
}

func convertResponseFromREST(resp *v1alpha1.VerifyAttestationResponse) (*verifier.VerifyAttestationResponse, error) {
	token, err := encoding.DecodeString(resp.ClaimsToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decode VerifyAttestationResponse.ClaimsToken: %w", err)
	}
	return &verifier.VerifyAttestationResponse{
		ClaimsToken: token,
	}, nil
}
