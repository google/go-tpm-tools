package rest

import (
	"fmt"
	"strings"
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
