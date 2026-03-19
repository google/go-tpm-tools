package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestProvenance(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		serverResponse string
		serverStatus   int
		vaildOutput    bool
		wantErr        string
	}{
		{
			name:           "Direct PPID Success",
			args:           []string{"provenance", "--ppid", "test-ppid", "--bucket", "test-bucket"},
			serverResponse: `{"location": "us-east1"}`,
			serverStatus:   http.StatusOK,
			vaildOutput:    true,
		},
		{
			name:           "No Such Bucket",
			args:           []string{"provenance", "--ppid", "test-ppid", "--bucket", "test-bucket"},
			serverResponse: "NoSuchBucket",
			serverStatus:   http.StatusNotFound,
			wantErr:        "GCS request failed: bucket 'test-bucket' not found (404)",
		},
		{
			name:           "No Such Key",
			args:           []string{"provenance", "--ppid", "test-ppid", "--bucket", "test-bucket"},
			serverResponse: "NoSuchKey",
			serverStatus:   http.StatusNotFound,
			wantErr:        "GCS request failed: file 'test-ppid.json' not found in bucket 'test-bucket' (404)",
		},
		{
			name:           "Server Error",
			args:           []string{"provenance", "--ppid", "test-ppid", "--bucket", "test-bucket"},
			serverResponse: "internal error",
			serverStatus:   http.StatusInternalServerError,
			wantErr:        "GCS request failed with status: 500 Internal Server Error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.serverStatus)
				fmt.Fprint(w, tt.serverResponse)
			}))
			defer ts.Close()

			oldGcsURL := gcsBaseURL
			gcsBaseURL = ts.URL
			defer func() { gcsBaseURL = oldGcsURL }()

			outFile := filepath.Join(t.TempDir(), "output.json")
			fullArgs := append(tt.args, "--output", outFile)

			RootCmd.SetArgs(fullArgs)
			err := RootCmd.Execute()

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if err.Error() != tt.wantErr {
					t.Errorf("expected error %q, got %q", tt.wantErr, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("Execute failed: %v", err)
				}
				if tt.vaildOutput {
					b, err := os.ReadFile(outFile)
					if err != nil {
						t.Fatalf("failed to read output file: %v", err)
					}
					if string(b) != tt.serverResponse {
						t.Errorf("expected %s, got %s", tt.serverResponse, string(b))
					}
				}
			}
		})
	}
}
