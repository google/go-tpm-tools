package util

import (
	"testing"

	"cloud.google.com/go/compute/metadata"
	"github.com/google/go-cmp/cmp"
)

func TestPrincipleFetcher(t *testing.T) {
	var dummyMetaInstance = Instance{ProjectID: "test-project", ProjectNumber: "1922337278274", Zone: "us-central-1a", InstanceID: "12345678", InstanceName: "default"}
	mockMdsServer, err := NewMetadataServer(dummyMetaInstance)
	if err != nil {
		t.Error(err)
	}
	defer mockMdsServer.Stop()
	mdsClient := metadata.NewClient(nil)
	gotTokens, err := PrincipalFetcher("test_audience", mdsClient)
	if err != nil {
		t.Error(err)
	}
	wantTokens := [][]byte{[]byte("test_jwt_token")}
	if !cmp.Equal(wantTokens, gotTokens) {
		t.Error("ID Token Mismatch")
	}
}

func TestGetRegion(t *testing.T) {
	var dummyMetaInstance = Instance{ProjectID: "test-project", ProjectNumber: "1922337278274", Zone: "us-central-1a", InstanceID: "12345678", InstanceName: "default"}
	mockMdsServer, err := NewMetadataServer(dummyMetaInstance)
	if err != nil {
		t.Error(err)
	}
	defer mockMdsServer.Stop()
	// Metadata Server (MDS). A GCP specific client.
	mdsClient := metadata.NewClient(nil)
	region, err := GetRegion(mdsClient)
	if err != nil {
		t.Errorf("Failed to GetRegion %s", err)
	}
	if region != "us-central" {
		t.Error("Region Mismatch")
	}
}
