// Package rest contains the code to use the REST-based Google API
package rest

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/go-tpm-tools/launcher/verifier"

	v1alpha1 "google.golang.org/api/confidentialcomputing/v1alpha1"
	googleapi "google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

// BadRegionError indicates that:
//   - the requested Region cannot be used with this API
//   - other Regions _can_ be used with this API
type BadRegionError struct {
	RequestedRegion  string
	AvailableRegions []string
	err              error
}

func (e *BadRegionError) Error() string {
	return fmt.Sprintf(
		"invalid region %q, available regions are [%s]: %v",
		e.RequestedRegion, strings.Join(e.AvailableRegions, ", "), e.err,
	)
}

func (e *BadRegionError) Unwrap() error {
	return e.err
}

// NewClient creates a new REST client which is configured to perform
// attestations in a particular project and region. Returns a *BadRegionError
// if the requested project is valid, but the region is invalid.
func NewClient(ctx context.Context, projectID string, region string, opts ...option.ClientOption) (verifier.Client, error) {
	service, err := v1alpha1.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("can't create ConfidentialComputing v1alpha1 API client: %w", err)
	}

	projectName := fmt.Sprintf("projects/%s", projectID)
	locationName := fmt.Sprintf("%s/locations/%v", projectName, region)

	location, getErr := service.Projects.Locations.Get(locationName).Do()
	if getErr == nil {
		return &restClient{service, location}, nil
	}

	// If we can't get the location, try to list the locations. This handles
	// situations where the projectID is invalid.
	list, listErr := service.Projects.Locations.List(projectName).Do()
	if listErr != nil {
		return nil, fmt.Errorf("listing regions in project %q: %w", projectID, listErr)
	}

	// The project is valid, but can't get the desired region.
	regions := make([]string, len(list.Locations))
	for i, loc := range list.Locations {
		regions[i] = loc.LocationId
	}
	return nil, &BadRegionError{
		RequestedRegion:  region,
		AvailableRegions: regions,
		err:              getErr,
	}
}

type restClient struct {
	service  *v1alpha1.Service
	location *v1alpha1.Location
}

type errorOverride struct {
	message   string
	showError bool
}

// CreateChallenge implements verifier.Client
func (c *restClient) CreateChallenge(_ context.Context) (*verifier.Challenge, error) {
	// Pass an empty Challenge for the input (all params are output-only)
	chal, err := c.service.Projects.Locations.Challenges.Create(
		c.location.Name,
		&v1alpha1.Challenge{},
	).Do()
	if err != nil {
		genericError := "error calling v1alpha1.CreateChallenge"
		overrideMap := map[int]errorOverride{
			http.StatusBadRequest:          {message: "bad request", showError: true},
			http.StatusInternalServerError: {message: "internal", showError: true},
			http.StatusLoopDetected:        {message: genericError, showError: false},
		}
		return nil, handleError(err.(*googleapi.Error), genericError, overrideMap)
	}
	return convertChallengeFromREST(chal)
}

// VerifyAttestation implements verifier.Client
func (c *restClient) VerifyAttestation(_ context.Context, request verifier.VerifyAttestationRequest) (*verifier.VerifyAttestationResponse, error) {
	if request.Challenge == nil || request.Attestation == nil {
		return nil, fmt.Errorf("nil value provided in challenge")
	}
	response, err := c.service.Projects.Locations.Challenges.VerifyAttestation(
		request.Challenge.Name,
		convertRequestToREST(request),
	).Do()
	if err != nil {
		genericError := "error calling v1alpha1.VerifyAttestation"
		overrideMap := map[int]errorOverride{
			http.StatusBadRequest:          {message: "bad request", showError: true},
			http.StatusInternalServerError: {message: "internal", showError: true},
			http.StatusLoopDetected:        {message: genericError, showError: false},
		}
		return nil, handleError(err.(*googleapi.Error), genericError, overrideMap)
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

func handleError(apiErr *googleapi.Error, genericError string, errorOverrides map[int]errorOverride) error {
	errorOverride, exists := errorOverrides[apiErr.Code]
	if exists {
		if !errorOverride.showError {
			return fmt.Errorf(errorOverride.message)
		}
		return fmt.Errorf(errorOverride.message+": %v", apiErr)
	}

	return fmt.Errorf(genericError+": %v", apiErr)
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
