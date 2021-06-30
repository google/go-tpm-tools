package server

import (
	"fmt"
	"net/url"

	pb "github.com/google/go-tpm-tools/proto/attest"
)

// GCEInstanceURL returns a Google API URL to the specified instance. This URL
// can then be used with GCE instance APIs.
func GCEInstanceURL(i *pb.GCEInstanceInfo) string {
	return fmt.Sprintf(
		"https://www.googleapis.com/compute/v1/projects/%s/zones/%s/instances/%s",
		url.PathEscape(i.GetProjectId()),
		url.PathEscape(i.GetZone()),
		url.PathEscape(i.GetInstanceName()), // Can use either the name or id here
	)
}
