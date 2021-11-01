package server

import "strings"

var fatalError string = "fatal: invalid GroupedError"

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
