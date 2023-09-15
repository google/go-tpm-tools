package rest

import (
	"testing"

	confidentialcomputingpb "cloud.google.com/go/confidentialcomputing/apiv1/confidentialcomputingpb"
	"github.com/google/go-tpm-tools/launcher/verifier"
)

// Make sure our conversion function can handle empty values.
func TestConvertEmpty(t *testing.T) {
	if _, err := convertChallengeFromREST(&confidentialcomputingpb.Challenge{}); err != nil {
		t.Errorf("Converting empty challenge: %v", err)
	}
	_ = convertRequestToREST(verifier.VerifyAttestationRequest{})
	if _, err := convertResponseFromREST(&confidentialcomputingpb.VerifyAttestationResponse{}); err != nil {
		t.Errorf("Converting empty challenge: %v", err)
	}
}
