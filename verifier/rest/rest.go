// Package rest contains the code to use the REST-based Google API
package rest

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"strings"

	sabi "github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/sevsnp"
	tabi "github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tpm-tools/verifier"
	"github.com/google/go-tpm-tools/verifier/models"
	"github.com/google/go-tpm-tools/verifier/oci"

	v1 "cloud.google.com/go/confidentialcomputing/apiv1"
	ccpb "cloud.google.com/go/confidentialcomputing/apiv1/confidentialcomputingpb"
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
	req := &ccpb.CreateChallengeRequest{
		Parent:    c.location.Name,
		Challenge: &ccpb.Challenge{},
	}
	chal, err := c.v1Client.CreateChallenge(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("calling v1.CreateChallenge in %v: %w", c.location.LocationId, err)
	}
	return convertChallengeFromREST(chal)
}

// VerifyAttestation implements verifier.Client
func (c *restClient) VerifyAttestation(ctx context.Context, request verifier.VerifyAttestationRequest) (*verifier.VerifyAttestationResponse, error) {
	if request.Challenge == nil {
		return nil, fmt.Errorf("nil value provided in challenge")
	}

	if request.Attestation == nil && request.TDCCELAttestation == nil {
		return nil, fmt.Errorf("neither TPM nor TDX attestation is present")
	} else if request.Attestation != nil && request.TDCCELAttestation != nil {
		return nil, fmt.Errorf("both TPM and TDX attestation are present, only one should be present in the attestation request")
	}

	req := convertRequestToREST(request)
	req.Challenge = request.Challenge.Name

	response, err := c.v1Client.VerifyAttestation(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("calling v1.VerifyAttestation in %v: %w", c.location.LocationId, err)
	}
	return convertResponseFromREST(response)
}

var encoding = base64.StdEncoding

func convertChallengeFromREST(chal *ccpb.Challenge) (*verifier.Challenge, error) {
	nonce, err := encoding.DecodeString(chal.TpmNonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Challenge.Nonce: %w", err)
	}
	return &verifier.Challenge{
		Name:  chal.Name,
		Nonce: nonce,
	}, nil
}

func convertTokenOptionsToREST(tokenOpts *models.TokenOptions) *ccpb.TokenOptions {
	if tokenOpts == nil {
		return nil
	}

	optsPb := &ccpb.TokenOptions{
		Audience: tokenOpts.Audience,
		Nonce:    tokenOpts.Nonces,
	}

	switch tokenOpts.TokenType {
	case "OIDC":
		optsPb.TokenType = ccpb.TokenType_TOKEN_TYPE_OIDC
	case "PKI":
		optsPb.TokenType = ccpb.TokenType_TOKEN_TYPE_PKI
	case "LIMITED_AWS":
		optsPb.TokenType = ccpb.TokenType_TOKEN_TYPE_LIMITED_AWS
	case "AWS_PRINCIPALTAGS":
		optsPb.TokenType = ccpb.TokenType_TOKEN_TYPE_AWS_PRINCIPALTAGS
		setAwsPrincipalTagOptions(tokenOpts, optsPb)
	default:
		optsPb.TokenType = ccpb.TokenType_TOKEN_TYPE_UNSPECIFIED
	}

	return optsPb
}

func convertRequestToREST(request verifier.VerifyAttestationRequest) *ccpb.VerifyAttestationRequest {
	idTokens := make([]string, len(request.GcpCredentials))
	for i, token := range request.GcpCredentials {
		idTokens[i] = string(token)
	}

	signatures := make([]*ccpb.ContainerImageSignature, len(request.ContainerImageSignatures))
	for i, sig := range request.ContainerImageSignatures {
		signature, err := convertOCISignatureToREST(sig)
		if err != nil {
			log.Printf("failed to convert OCI signature [%v] to ContainerImageSignature proto: %v", sig, err)
			continue
		}
		signatures[i] = signature
	}

	verifyReq := &ccpb.VerifyAttestationRequest{
		GcpCredentials: &ccpb.GcpCredentials{
			ServiceAccountIdTokens: idTokens,
		},
		ConfidentialSpaceInfo: &ccpb.ConfidentialSpaceInfo{
			SignedEntities: []*ccpb.SignedEntity{{ContainerImageSignatures: signatures}},
		},
		TokenOptions: convertTokenOptionsToREST(request.TokenOptions),
	}

	if request.Attestation != nil {
		// TPM attestation route
		quotes := make([]*ccpb.TpmAttestation_Quote, len(request.Attestation.GetQuotes()))
		for i, quote := range request.Attestation.GetQuotes() {
			pcrVals := map[int32][]byte{}
			for idx, val := range quote.GetPcrs().GetPcrs() {
				pcrVals[int32(idx)] = val
			}

			quotes[i] = &ccpb.TpmAttestation_Quote{
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

		verifyReq.TpmAttestation = &ccpb.TpmAttestation{
			Quotes:            quotes,
			TcgEventLog:       request.Attestation.GetEventLog(),
			CanonicalEventLog: request.Attestation.GetCanonicalEventLog(),
			AkCert:            request.Attestation.GetAkCert(),
			CertChain:         certs,
		}

		if request.Attestation.GetSevSnpAttestation() != nil {
			sevsnp, err := convertSEVSNPProtoToREST(request.Attestation.GetSevSnpAttestation())
			if err != nil {
				log.Fatalf("Failed to convert SEVSNP proto to API proto: %v", err)
			}
			verifyReq.TeeAttestation = sevsnp
		}

		if request.Attestation.GetTdxAttestation() != nil {
			tdx, err := convertTDXProtoToREST(request.Attestation.GetTdxAttestation())
			if err != nil {
				log.Fatalf("Failed to convert TD quote proto to API proto: %v", err)
			}
			verifyReq.TeeAttestation = tdx
		}
	} else if request.TDCCELAttestation != nil {
		// TDX attestation route
		// still need AK for GCE info!
		verifyReq.TpmAttestation = &ccpb.TpmAttestation{
			AkCert:    request.TDCCELAttestation.AkCert,
			CertChain: request.TDCCELAttestation.IntermediateCerts,
		}

		verifyReq.TeeAttestation = &ccpb.VerifyAttestationRequest_TdCcel{
			TdCcel: &ccpb.TdxCcelAttestation{
				TdQuote:           request.TDCCELAttestation.TdQuote,
				CcelAcpiTable:     request.TDCCELAttestation.CcelAcpiTable,
				CcelData:          request.TDCCELAttestation.CcelData,
				CanonicalEventLog: request.TDCCELAttestation.CanonicalEventLog,
			},
		}
	}

	return verifyReq
}

func convertResponseFromREST(resp *ccpb.VerifyAttestationResponse) (*verifier.VerifyAttestationResponse, error) {
	token := []byte(resp.GetOidcClaimsToken())
	return &verifier.VerifyAttestationResponse{
		ClaimsToken: token,
		PartialErrs: resp.PartialErrors,
	}, nil
}

func convertOCISignatureToREST(signature oci.Signature) (*ccpb.ContainerImageSignature, error) {
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
	return &ccpb.ContainerImageSignature{
		Payload:   payload,
		Signature: sigBytes,
	}, nil
}

func convertSEVSNPProtoToREST(att *sevsnp.Attestation) (*ccpb.VerifyAttestationRequest_SevSnpAttestation, error) {
	auxBlob := sabi.CertsFromProto(att.GetCertificateChain()).Marshal()
	rawReport, err := sabi.ReportToAbiBytes(att.GetReport())
	if err != nil {
		return nil, err
	}
	return &ccpb.VerifyAttestationRequest_SevSnpAttestation{
		SevSnpAttestation: &ccpb.SevSnpAttestation{
			AuxBlob: auxBlob,
			Report:  rawReport,
		},
	}, nil
}

func convertTDXProtoToREST(att *tdx.QuoteV4) (*ccpb.VerifyAttestationRequest_TdCcel, error) {
	rawQuote, err := tabi.QuoteToAbiBytes(att)
	if err != nil {
		return nil, err
	}
	return &ccpb.VerifyAttestationRequest_TdCcel{
		TdCcel: &ccpb.TdxCcelAttestation{
			TdQuote: rawQuote,
		},
	}, nil
}

func setAwsPrincipalTagOptions(request *models.TokenOptions, optsPb *ccpb.TokenOptions) {
	if !request.HasAWSPrincipalTagOptions() {
		return
	}
	optsPb.TokenTypeOptions = &ccpb.TokenOptions_AwsPrincipalTagsOptions_{
		AwsPrincipalTagsOptions: &ccpb.TokenOptions_AwsPrincipalTagsOptions{},
	}

	if !request.PrincipalTagOptions.HasAllowedPrincipalTags() {
		return
	}
	optsPb.GetAwsPrincipalTagsOptions().AllowedPrincipalTags = &ccpb.TokenOptions_AwsPrincipalTagsOptions_AllowedPrincipalTags{}

	if !request.PrincipalTagOptions.AllowedPrincipalTags.HasContainerImageSignatures() {
		return
	}

	optsPb.GetAwsPrincipalTagsOptions().GetAllowedPrincipalTags().ContainerImageSignatures = &ccpb.TokenOptions_AwsPrincipalTagsOptions_AllowedPrincipalTags_ContainerImageSignatures{
		KeyIds: request.PrincipalTagOptions.AllowedPrincipalTags.ContainerImageSignatures.KeyIDs,
	}
}
