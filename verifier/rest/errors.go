package rest

import (
	"fmt"
	"strings"

	confidentialcomputingpb "cloud.google.com/go/confidentialcomputing/apiv1/confidentialcomputingpb"
	"google.golang.org/api/googleapi"
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

type VerifyAttestationError struct {
	request *confidentialcomputingpb.VerifyAttestationRequest
	err     error
}

func NewVerifyAttestationError(request *confidentialcomputingpb.VerifyAttestationRequest, err error) *VerifyAttestationError {
	return &VerifyAttestationError{
		request: request,
		err:     err,
	}
}

func (e *VerifyAttestationError) Error() string {
	return fmt.Sprintf("VerifyAttestationError from request [%+v]: %v", e.request, e.err)
}

func (e *VerifyAttestationError) Unwrap() error {
	return e.err
}

func (e *VerifyAttestationError) StatusCode() int {
	if gErr, ok := e.err.(*googleapi.Error); ok {
		return int(gErr.Code)
	}
	return 0
}
