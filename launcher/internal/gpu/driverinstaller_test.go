package gpu

import (
	"os"
	"path"
	"strings"
	"testing"

	"cos.googlesource.com/cos/tools.git/src/cmd/cos_gpu_installer/deviceinfo"
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

func TestCheckGPUSupport(t *testing.T) {
	tests := []struct {
		name      string
		gpuType   deviceinfo.GPUType
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "H100 supported",
			gpuType: deviceinfo.H100,
			wantErr: false,
		},
		{
			name:    "B200 supported",
			gpuType: deviceinfo.B200,
			wantErr: false,
		},
		{
			name:    "RTX PRO 6000 supported",
			gpuType: deviceinfo.RTX_PRO_6000,
			wantErr: false,
		},
		{
			name:      "Unrecognized GPU (Others)",
			gpuType:   deviceinfo.Others,
			wantErr:   true,
			errSubstr: "failed to get the GPU type info: unrecognized GPU",
		},
		{
			name:      "Unsupported GPU (T4)",
			gpuType:   deviceinfo.T4,
			wantErr:   true,
			errSubstr: "unsupported GPU type NVIDIA_TESLA_T4 for Confidential Computing (only supported for H100[a3-highgpu-1g], B200[a4-highgpu-8g], and RTX PRO 6000[g4-standard-48])",
		},
		{
			name:      "No GPU",
			gpuType:   deviceinfo.NO_GPU,
			wantErr:   true,
			errSubstr: "failed to get the GPU type info: no GPU detected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkGPUSupport(tt.gpuType)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkGPUSupport(%v) error = %v, wantErr %v", tt.gpuType, err, tt.wantErr)
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.errSubstr) {
				t.Errorf("checkGPUSupport(%v) error = %v, expected to contain %q", tt.gpuType, err, tt.errSubstr)
			}
		})
	}
}
