package proto

import (
	"fmt"
	"net/url"
)

// InstanceURL returns a Google API URL to the specified instance. This URL can
// then be used with GCE instance APIs.
func (x *GceInstanceInfo) InstanceURL() string {
	return fmt.Sprintf(
		"https://www.googleapis.com/compute/v1/projects/%s/zones/%s/instances/%s",
		url.PathEscape(x.GetProjectId()),
		url.PathEscape(x.GetZone()),
		url.PathEscape(x.GetInstanceName()), // Can use either the name or id here
	)
}
