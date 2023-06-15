package rest

import (
	"net/http"
	"testing"

	"github.com/google/go-tpm-tools/launcher/verifier"
	v1alpha1 "google.golang.org/api/confidentialcomputing/v1alpha1"
	googleapi "google.golang.org/api/googleapi"
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

func TestHandleError(t *testing.T) {
	testcases := []struct {
		name            string
		apiError        *googleapi.Error
		expectedMessage string
		overridesMap    map[int]errorOverride
	}{
		{
			name:            "err500",
			apiError:        &googleapi.Error{Code: http.StatusInternalServerError, Message: "This is a internal server error (500)"},
			expectedMessage: "internal: googleapi: Error 500: This is a internal server error (500)",
			overridesMap: map[int]errorOverride{
				http.StatusInternalServerError: {message: "internal", showError: true},
			},
		},
		{
			name:            "err400",
			apiError:        &googleapi.Error{Code: http.StatusBadRequest, Message: "This is a bad request error (400)"},
			expectedMessage: "bad request: googleapi: Error 400: This is a bad request error (400)",
			overridesMap: map[int]errorOverride{
				http.StatusBadRequest: {message: "bad request", showError: true},
			},
		},
		{
			name:            "err409",
			apiError:        &googleapi.Error{Code: http.StatusConflict, Message: "This is a conflict error (409)"},
			expectedMessage: "bar",
			overridesMap: map[int]errorOverride{
				http.StatusConflict: {message: "bar", showError: false},
			},
		},
		{
			name:            "err502",
			apiError:        &googleapi.Error{Code: http.StatusBadGateway, Message: "This is a bad gateway error (502)"},
			expectedMessage: "foo: googleapi: Error 502: This is a bad gateway error (502)",
			overridesMap:    map[int]errorOverride{},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			responseErrorInternal := handleError(tc.apiError, "foo", tc.overridesMap)
			if !(responseErrorInternal.Error() == tc.expectedMessage) {
				t.Errorf("Issue handling errors: %v", responseErrorInternal)
			}
		})
	}
}
