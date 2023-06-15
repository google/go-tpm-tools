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
	err500 := &googleapi.Error{Code: http.StatusInternalServerError, Message: "This is a internal server error (500)"}
	err400 := &googleapi.Error{Code: http.StatusBadRequest, Message: "This is a bad request error (400)"}
	err409 := &googleapi.Error{Code: http.StatusConflict, Message: "This is a conflict error (409)"}
	err502 := &googleapi.Error{Code: http.StatusBadGateway, Message: "This is a bad gateway error (502)"}
	overridesMap := map[int]errorOverride{
		http.StatusBadRequest:          {message: "bad request", showError: true},
		http.StatusInternalServerError: {message: "internal", showError: true},
		http.StatusConflict:            {message: "bar", showError: false},
	}
	responseErrorInternal := handleError(err500, "foo", overridesMap)
	if !(responseErrorInternal.Error() == "internal: googleapi: Error 500: This is a internal server error (500)") {
		t.Errorf("Issue handling errors: %v", responseErrorInternal)
	}

	responseErrorBadReq := handleError(err400, "foo", overridesMap)
	if !(responseErrorBadReq.Error() == "bad request: googleapi: Error 400: This is a bad request error (400)") {
		t.Errorf("Issue handling errors: %v", responseErrorBadReq)
	}

	responseErrorConflict := handleError(err409, "foo", overridesMap)
	if !(responseErrorConflict.Error() == "bar") {
		t.Errorf("Issue handling errors: %v", responseErrorConflict)
	}

	responseErrorBadGateway := handleError(err502, "foo", overridesMap)
	if !(responseErrorBadGateway.Error() == "foo: googleapi: Error 502: This is a bad gateway error (502)") {
		t.Errorf("Issue handling errors: %v", responseErrorBadGateway)
	}
}
