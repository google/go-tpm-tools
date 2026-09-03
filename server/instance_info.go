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

// GCEInstanceResourceName returns the Compute Engine full resource name for the
// specified instance using its project number and instance id.
func GCEInstanceResourceName(i *pb.GCEInstanceInfo) string {
	return fmt.Sprintf(
		"//compute.googleapis.com/projects/%d/zones/%s/instances/%d",
		i.GetProjectNumber(),
		url.PathEscape(i.GetZone()),
		i.GetInstanceId(),
	)
}
