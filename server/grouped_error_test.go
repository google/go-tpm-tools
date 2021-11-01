package server

import (
	"errors"
	"fmt"
	"testing"
)

func TestGroupedError(t *testing.T) {
	var gErr GroupedError
	gErr.Errors = append(gErr.Errors, errors.New("error1"))
	gErr.Errors = append(gErr.Errors, errors.New("error2"))
	gErr.Errors = append(gErr.Errors, fmt.Errorf("fmted error"))
	gErr.Errors = append(gErr.Errors, fmt.Errorf("wrapped: %w", errors.New("error3")))
	gErr.Prefix = "failed action:"

	expected := `failed action:
error1
error2
fmted error
wrapped: error3`

	if gErr.Error() != expected {
		t.Errorf("error string output (%s) did not match expected (%s)",
			gErr.Error(), expected)
	}
}

func TestEmptyGroupedError(t *testing.T) {
	outErr := GroupedError{Prefix: "foo:", Errors: []error{}}
	if outErr.Error() != fatalError {
		t.Errorf("error string output (%s) did not match fatal error (%s)",
			outErr.Error(), fatalError)
	}
}

func TestCreateGroupedErrorFail(t *testing.T) {
	outErr := createGroupedError("foo:", []error{})
	if outErr != nil {
		t.Errorf("expected nil error!")
	}
}
