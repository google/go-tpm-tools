package util

import (
	"fmt"
	"net/http"
	"strings"
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

func TestValidateCustomNonceAndAudienceFromRequest(t *testing.T) {
	testCases := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{
			name:    "empty body",
			body:    "{}",
			wantErr: false,
		},
		{
			name:    "single nonce - should not panic",
			body:    `{"tokenOptions": {"nonce": ["single_nonce"]}}`,
			wantErr: true,
		},
		{
			name:    "empty nonce list - should not panic",
			body:    `{"tokenOptions": {"nonce": []}}`,
			wantErr: false,
		},
		{
			name:    "valid nonce and audience",
			body:    fmt.Sprintf(`{"tokenOptions": {"nonce": ["%s", "%s"], "audience": "%s"}}`, FakeCustomNonce[0], FakeCustomNonce[1], FakeCustomAudience),
			wantErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, "/verify", strings.NewReader(tc.body))
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			err = validateCustomNonceAndAudienceFromRequest(req)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateCustomNonceAndAudienceFromRequest() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

