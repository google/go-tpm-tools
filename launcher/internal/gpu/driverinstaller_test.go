package gpu

import (
	"os"
	"path"
	"strings"
	"testing"
)

func TestVerifyDriverDigest(t *testing.T) {
	tests := []struct {
		name        string
		fileContent string
		refDigest   string
		wantErr     bool
		errSubstr   string
	}{
		{
			name:        "Driver digest matches",
			fileContent: "test-digest",
			refDigest:   "8edf273aa28919d86f9f0ab68b1f267280821a3251c281d19748f940c180d27f",
			wantErr:     false,
		},
		{
			name:        "Driver digest mismatch",
			fileContent: "test-digest",
			refDigest:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			wantErr:     true,
			errSubstr:   "GPU driver digest verification failed",
		},
		{
			name:        "Empty reference driver digest",
			fileContent: "test-digest",
			wantErr:     true,
			errSubstr:   "GPU driver digest verification failed",
		},
		{
			name:      "Installed driver file does not exist",
			refDigest: "8edf273aa28919d86f9f0ab68b1f267280821a3251c281d19748f940c180d27f",
			wantErr:   true,
			errSubstr: "failed to read the file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			filePath := path.Join(tempDir, "file.run")

			if tt.name != "Installed driver file does not exist" {
				err := os.WriteFile(filePath, []byte(tt.fileContent), 0644)
				if err != nil {
					t.Fatalf("failed to write to the driver digest testfile %s: %v", filePath, err)
				}
			}
			err := verifyDriverDigest(filePath, tt.refDigest)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyDriverDigest() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.errSubstr) {
				t.Errorf("VerifyDriverDigest() error message %s is expected to contain %s", err.Error(), tt.errSubstr)
			}
		})
	}
}
