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

func TestContainsOnlySubstring(t *testing.T) {
	wholeString := "err error errorz"
	err := errors.New(wholeString)
	outErr := GroupedError{Prefix: "foo:", Errors: []error{err}}
	if !outErr.containsOnlySubstring("error") {
		t.Errorf("expected a match for substring")
	}
	if !outErr.containsOnlySubstring("err") {
		t.Errorf("expected a match for substring")
	}
	if !outErr.containsOnlySubstring("") {
		t.Errorf("expected a match for substring")
	}
	if !outErr.containsOnlySubstring(wholeString) {
		t.Errorf("expected a match for substring")
	}
}

func TestContainsOnlySubstringsFalse(t *testing.T) {
	wholeString := "err error errorz"
	err := errors.New(wholeString)
	outErr := GroupedError{Prefix: "foo:", Errors: []error{err}}

	tests := []struct {
		name      string
		substring string
	}{
		{"AdditionalCharacterStart", "." + wholeString},
		{"AdditionalCharacterEnd", wholeString + "."},
		{"RemovedCharacter", wholeString[:5] + wholeString[6:]},
		{"ReplacedCharacter", wholeString[:5] + "." + wholeString[6:]},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if outErr.containsOnlySubstring(test.substring) {
				t.Errorf("expected failed matching for substring")
			}

		})
	}
}

func TestContainsKnownSubstrings(t *testing.T) {
	err := errors.New("err error errorz")
	err2 := errors.New("new newww newzz")
	err3 := errors.New("iss issue issues")
	outErr := GroupedError{Prefix: "foo:", Errors: []error{err, err2, err3}}
	if !outErr.containsKnownSubstrings([]string{"error", " newzz", " issue "}) {
		t.Errorf("expected a match for known substrings")
	}
}

func TestContainsKnownSubstringsFalse(t *testing.T) {
	err := errors.New("err error errorz")
	err2 := errors.New("new newww newzz")
	err3 := errors.New("iss issue issues")
	outErr := GroupedError{Prefix: "foo:", Errors: []error{err, err2, err3}}

	tests := []struct {
		name       string
		substrings []string
	}{
		{"NoSubstrings", []string{}},
		{"OneEmptySubstring", []string{""}},
		// Should fail, since there is overlap between substrings.
		{"AllEmptySubstrings", []string{"", "", ""}},
		{"FewerSubstrings", []string{"err"}},
		{"FewerSubstrings2", []string{"error", " issue "}},
		{"MoreSubstrings", []string{"error", " newzz", " issue ", " issues"}},
		{"MoreSubstrings5", []string{"error", " newzz", " issue ", " issues", "err"}},
		{"OverlappingSubstrings", []string{"error", " err", " issue "}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if outErr.containsKnownSubstrings(test.substrings) {
				t.Errorf("expected failed matching for known substrings")
			}

		})
	}
}
