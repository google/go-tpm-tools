package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"

	"cloud.google.com/go/compute/metadata"
)

const metadataHostEnv = "GCE_METADATA_HOST"

// Instance struct for supported fake values for metadata server.
type Instance struct {
	ProjectID     string
	ProjectNumber string
	InstanceID    string
	InstanceName  string
	Zone          string
}

// MetadataServer provides fake implementation for the GCE metadata server.
type MetadataServer struct {
	server             *httptest.Server
	oldMetadataHostEnv string
	responses          map[string]string
}

// NewMetadataServer starts and hooks up a Server, serving env.
// data is the mock Instance data the metadata server will respond with.
func NewMetadataServer(data Instance) (*MetadataServer, error) {
	resp := map[string]string{}
	resp["project/project-id"] = data.ProjectID
	resp["project/numeric-project-id"] = data.ProjectNumber
	resp["instance/id"] = data.InstanceID
	resp["instance/zone"] = data.Zone
	resp["instance/name"] = data.InstanceName

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := "/computeMetadata/v1/"
		uri := strings.TrimPrefix(r.URL.Path, path)
		if uri != "" {
			res, found := resp[uri]
			if found {
				w.Write([]byte(res))
				return
			}
		}
		http.Error(w, http.StatusText(http.StatusNotImplemented), http.StatusNotImplemented)
	})
	httpServer := httptest.NewServer(handler)

	old := os.Getenv(metadataHostEnv)
	s := &MetadataServer{oldMetadataHostEnv: old, server: httpServer, responses: resp}

	os.Setenv(metadataHostEnv, strings.TrimPrefix(s.server.URL, "http://"))

	if !metadata.OnGCE() {
		s.Stop()
		return nil, fmt.Errorf("gcpmocks.NewMetadataServer: failed to fake being on a GCE instance")
	}
	return s, nil
}

// Stop shuts down the server and restores original metadataHostEnv env var.
func (s *MetadataServer) Stop() {
	os.Setenv(metadataHostEnv, s.oldMetadataHostEnv)

	s.server.Close()
}
