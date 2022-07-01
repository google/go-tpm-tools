package rest

import (
	"testing"

	"github.com/google/go-tpm-tools/launcher/verifier"
	v1alpha1 "google.golang.org/api/confidentialcomputing/v1alpha1"
)

// Make sure our conversion function can handle empty values.
func TestConvertEmpty(t *testing.T) {
	if _, err := convertChallengeFromREST(&v1alpha1.Challenge{}); err != nil {
		t.Errorf("Converting empty challenge: %v", err)
	}
	_ = convertRequestToREST(verifier.VerifyAttestationRequest{})
	if _, err := convertResponseFromREST(&v1alpha1.VerifyAttestationResponse{}); err != nil {
		t.Errorf("Converting empty challenge: %v", err)
	}
}
