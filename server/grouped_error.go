package server

import "strings"

var fatalError = "fatal: invalid GroupedError"

// GroupedError collects related errors and exposes them as a single error.
// Users can inspect the `Errors` field for details on the suberrors.
type GroupedError struct {
	// The prefix string returned by `Error()`, followed by the grouped errors.
	Prefix string
	Errors []error
}

func (gErr *GroupedError) Error() string {
	if len(gErr.Errors) == 0 {
		return fatalError
	}
	var sb strings.Builder
	for _, err := range gErr.Errors {
		sb.WriteString("\n")
		sb.WriteString(err.Error())
	}
	return gErr.Prefix + sb.String()
}

func createGroupedError(prefix string, errors []error) error {
	if len(errors) == 0 {
		return nil
	}
	return &GroupedError{Prefix: prefix, Errors: errors}
}

func (gErr *GroupedError) containsSubstring(substr string) bool {
	for _, err := range gErr.Errors {
		if strings.Contains(err.Error(), substr) {
			return true
		}
	}
	return false
}

func (gErr *GroupedError) containsOnlySubstring(substr string) bool {
	if len(gErr.Errors) != 1 {
		return false
	}
	return gErr.containsSubstring(substr)
}
