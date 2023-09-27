// Package rest contains the code to use the REST-based Google API
package rest

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"strings"

	"github.com/google/go-tpm-tools/launcher/internal/oci"
	"github.com/google/go-tpm-tools/launcher/verifier"

	v1 "cloud.google.com/go/confidentialcomputing/apiv1"
	confidentialcomputingpb "cloud.google.com/go/confidentialcomputing/apiv1/confidentialcomputingpb"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	locationpb "google.golang.org/genproto/googleapis/cloud/location"
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
	client, err := v1.NewRESTClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("can't create ConfidentialComputing v1 API client: %w", err)
	}

	projectName := fmt.Sprintf("projects/%s", projectID)
	locationName := fmt.Sprintf("%s/locations/%v", projectName, region)

	getReq := &locationpb.GetLocationRequest{
		Name: locationName,
	}
	location, getErr := client.GetLocation(ctx, getReq)
	if getErr == nil {
		return &restClient{client, location}, nil
	}

	// If we can't get the location, try to list the locations. This handles
	// situations where the projectID is invalid.
	listReq := &locationpb.ListLocationsRequest{
		Name: projectName,
	}
	listIter := client.ListLocations(ctx, listReq)

	// The project is valid, but can't get the desired region.
	var regions []string
	for {
		resp, err := listIter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("listing regions in project %q: %w", projectID, err)
		}
		regions = append(regions, resp.LocationId)
	}
	return nil, &BadRegionError{
		RequestedRegion:  region,
		AvailableRegions: regions,
		err:              getErr,
	}
}

type restClient struct {
	v1Client *v1.Client
	location *locationpb.Location
}

// CreateChallenge implements verifier.Client
func (c *restClient) CreateChallenge(ctx context.Context) (*verifier.Challenge, error) {
	// Pass an empty Challenge for the input (all params are output-only)
	req := &confidentialcomputingpb.CreateChallengeRequest{
		Parent:    c.location.Name,
		Challenge: &confidentialcomputingpb.Challenge{},
	}
	chal, err := c.v1Client.CreateChallenge(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("calling v1.CreateChallenge: %w", err)
	}
	return convertChallengeFromREST(chal)
}

// VerifyAttestation implements verifier.Client
func (c *restClient) VerifyAttestation(ctx context.Context, request verifier.VerifyAttestationRequest) (*verifier.VerifyAttestationResponse, error) {
	if request.Challenge == nil || request.Attestation == nil {
		return nil, fmt.Errorf("nil value provided in challenge")
	}
	req := convertRequestToREST(request)
	req.Challenge = request.Challenge.Name
	response, err := c.v1Client.VerifyAttestation(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("calling v1.VerifyAttestation: %w", err)
	}
	return convertResponseFromREST(response)
}

var encoding = base64.StdEncoding

func convertChallengeFromREST(chal *confidentialcomputingpb.Challenge) (*verifier.Challenge, error) {
	nonce, err := encoding.DecodeString(chal.TpmNonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Challenge.Nonce: %w", err)
	}
	return &verifier.Challenge{
		Name:  chal.Name,
		Nonce: nonce,
	}, nil
}

func convertRequestToREST(request verifier.VerifyAttestationRequest) *confidentialcomputingpb.VerifyAttestationRequest {
	idTokens := make([]string, len(request.GcpCredentials))
	for i, token := range request.GcpCredentials {
		idTokens[i] = string(token)
	}

	quotes := make([]*confidentialcomputingpb.TpmAttestation_Quote, len(request.Attestation.GetQuotes()))
	for i, quote := range request.Attestation.GetQuotes() {
		pcrVals := map[int32][]byte{}
		for idx, val := range quote.GetPcrs().GetPcrs() {
			pcrVals[int32(idx)] = val
		}

		quotes[i] = &confidentialcomputingpb.TpmAttestation_Quote{
			RawQuote:     quote.GetQuote(),
			RawSignature: quote.GetRawSig(),
			HashAlgo:     int32(quote.GetPcrs().GetHash()),
			PcrValues:    pcrVals,
		}
	}

	certs := make([][]byte, len(request.Attestation.GetIntermediateCerts()))
	for i, cert := range request.Attestation.GetIntermediateCerts() {
		certs[i] = cert
	}

	signatures := make([]*confidentialcomputingpb.ContainerImageSignature, len(request.ContainerImageSignatures))
	for i, sig := range request.ContainerImageSignatures {
		signature, err := convertOCISignatureToREST(sig)
		if err != nil {
			log.Printf("failed to convert OCI signature [%v] to ContainerImageSignature proto: %v", sig, err)
			continue
		}
		signatures[i] = signature
	}

	return &confidentialcomputingpb.VerifyAttestationRequest{
		GcpCredentials: &confidentialcomputingpb.GcpCredentials{
			ServiceAccountIdTokens: idTokens,
		},
		TpmAttestation: &confidentialcomputingpb.TpmAttestation{
			Quotes:            quotes,
			TcgEventLog:       request.Attestation.GetEventLog(),
			CanonicalEventLog: request.Attestation.GetCanonicalEventLog(),
			AkCert:            request.Attestation.GetAkCert(),
			CertChain:         certs,
		},
		ConfidentialSpaceInfo: &confidentialcomputingpb.ConfidentialSpaceInfo{
			SignedEntities: []*confidentialcomputingpb.SignedEntity{{ContainerImageSignatures: signatures}},
		},
	}
}

func convertResponseFromREST(resp *confidentialcomputingpb.VerifyAttestationResponse) (*verifier.VerifyAttestationResponse, error) {
	token := []byte(resp.GetOidcClaimsToken())
	return &verifier.VerifyAttestationResponse{
		ClaimsToken: token,
		PartialErrs: resp.PartialErrors,
	}, nil
}

func convertOCISignatureToREST(signature oci.Signature) (*confidentialcomputingpb.ContainerImageSignature, error) {
	payload, err := signature.Payload()
	if err != nil {
		return nil, err
	}
	b64Sig, err := signature.Base64Encoded()
	if err != nil {
		return nil, err
	}
	sigBytes, err := encoding.DecodeString(b64Sig)
	if err != nil {
		return nil, err
	}
	return &confidentialcomputingpb.ContainerImageSignature{
		Payload:   payload,
		Signature: sigBytes,
	}, nil
}
