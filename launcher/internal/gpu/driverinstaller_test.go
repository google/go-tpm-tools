package gpu

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"cos.googlesource.com/cos/tools.git/src/cmd/cos_gpu_installer/deviceinfo"
	"github.com/google/go-tpm-tools/proto/attest"
)

func TestGetInstallerImageReference(t *testing.T) {
	tests := []struct {
		name        string
		imageRefVal string
		wantRef     string
		wantErr     bool
		errSubstr   string
	}{
		{
			name:        "Successful read",
			imageRefVal: "gcr.io/google-containers/cos-gpu-installer:v1.2.3",
			wantRef:     "gcr.io/google-containers/cos-gpu-installer:v1.2.3",
			wantErr:     false,
		},
		{
			name:        "Successful read with whitespace",
			imageRefVal: "  gcr.io/google-containers/cos-gpu-installer:v1.2.4  \n",
			wantRef:     "gcr.io/google-containers/cos-gpu-installer:v1.2.4",
			wantErr:     false,
		},
		{
			name:        "File does not exist",
			imageRefVal: "",
			wantRef:     "",
			wantErr:     true,
			errSubstr:   "no such file or directory",
		},
		{
			name:        "Empty file",
			imageRefVal: "",
			wantRef:     "",
			wantErr:     true,
			errSubstr:   "empty value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			filePath := fmt.Sprintf("%s/installer_ref", tempDir)

			if tt.name != "File does not exist" {
				err := os.WriteFile(filePath, []byte(tt.imageRefVal), 0644)
				if err != nil {
					t.Fatalf("failed to write to the testfile %s: %v", filePath, err)
				}

			}

			ref, err := getInstallerImageReference(filePath)

			if (err != nil) != tt.wantErr {
				t.Errorf("getInstallerImageReference() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.errSubstr) {
				t.Errorf("getInstallerImageReference() err message %s is expected to contain %s", err.Error(), tt.errSubstr)
			}
			if ref != tt.wantRef {
				t.Errorf("getInstallerImageReference() got = %v, want %v", ref, tt.wantRef)
			}
		})
	}
}

func TestVerifyDriverInstallation(t *testing.T) {
	tests := []struct {
		name          string
		mockVerifyCmd NvidiaSmiCmdOutput
		wantErr       bool
		errSubstr     string
	}{
		{
			name:          "Verification succeeds",
			mockVerifyCmd: func() ([]byte, error) { return []byte("OK"), nil },
			wantErr:       false,
		},
		{
			name:          "Verification fails",
			mockVerifyCmd: func() ([]byte, error) { return []byte(""), fmt.Errorf("nvidia-smi verification failed") },
			wantErr:       true,
			errSubstr:     "failed to verify GPU driver installation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyDriverInstallation(tt.mockVerifyCmd)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyDriverInstallation() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.errSubstr) {
				t.Errorf("VerifyDriverInstallation() error message %s is expected to contain %s", err.Error(), tt.errSubstr)
			}
		})
	}
}

func TestSetGPUStateToReady(t *testing.T) {
	tests := []struct {
		name      string
		mockCmd   NvidiaSmiCmdOutput
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "Set GPU state succeeds",
			mockCmd: func() ([]byte, error) { return []byte("OK"), nil },
			wantErr: false,
		},
		{
			name:      "Set GPU state fails",
			mockCmd:   func() ([]byte, error) { return []byte(""), fmt.Errorf("nvidia-smi set state failed") },
			wantErr:   true,
			errSubstr: "failed to set the GPU state to ready",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := setGPUStateToReady(tt.mockCmd)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetGPUStateToReady() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.errSubstr) {
				t.Errorf("SetGPUStateToReady() error message %s is expected to contain %s", err.Error(), tt.errSubstr)
			}
		})
	}
}

func TestQueryCCMode(t *testing.T) {
	tests := []struct {
		name            string
		mockCCModeCmd   NvidiaSmiCmdOutput
		mockDevToolsCmd NvidiaSmiCmdOutput
		expectedCCMode  attest.GPUDeviceCCMode
		wantErr         bool
		errSubstr       string
	}{
		{
			name:            "CC ON, DevTools OFF",
			mockCCModeCmd:   func() ([]byte, error) { return []byte("CC status: ON"), nil },
			mockDevToolsCmd: func() ([]byte, error) { return []byte("DevTools Mode: OFF"), nil },
			expectedCCMode:  attest.GPUDeviceCCMode_ON,
			wantErr:         false,
		},
		{
			name:            "CC OFF, DevTools OFF",
			mockCCModeCmd:   func() ([]byte, error) { return []byte("CC status: OFF"), nil },
			mockDevToolsCmd: func() ([]byte, error) { return []byte("DevTools Mode: OFF"), nil },
			expectedCCMode:  attest.GPUDeviceCCMode_OFF,
			wantErr:         false,
		},
		{
			name:            "CC ON, DevTools ON",
			mockCCModeCmd:   func() ([]byte, error) { return []byte("CC status: ON"), nil },
			mockDevToolsCmd: func() ([]byte, error) { return []byte("DevTools Mode: ON"), nil },
			expectedCCMode:  attest.GPUDeviceCCMode_DEVTOOLS,
			wantErr:         false,
		},
		{
			name:            "Error getting CC Mode",
			mockCCModeCmd:   func() ([]byte, error) { return nil, fmt.Errorf("nvidia-smi CC mode error") },
			mockDevToolsCmd: func() ([]byte, error) { return []byte("DevTools Mode: OFF"), nil },
			expectedCCMode:  attest.GPUDeviceCCMode_UNSET,
			wantErr:         true,
			errSubstr:       "nvidia-smi CC mode error",
		},
		{
			name:            "Error getting DevTools Mode",
			mockCCModeCmd:   func() ([]byte, error) { return []byte("CC status: ON"), nil },
			mockDevToolsCmd: func() ([]byte, error) { return nil, fmt.Errorf("nvidia-smi DevTools mode error") },
			expectedCCMode:  attest.GPUDeviceCCMode_UNSET,
			wantErr:         true,
			errSubstr:       "nvidia-smi DevTools mode error",
		},
		{
			name:            "Invalid CC Mode Output",
			mockCCModeCmd:   func() ([]byte, error) { return []byte("CC status: INVALID"), nil },
			mockDevToolsCmd: func() ([]byte, error) { return []byte("DevTools Mode: ON"), nil },
			expectedCCMode:  attest.GPUDeviceCCMode_UNSET,
			wantErr:         false,
			errSubstr:       "unexpected CC status value",
		},
		{
			name:            "Invalid DevTools Mode Output",
			mockCCModeCmd:   func() ([]byte, error) { return []byte("CC status: ON"), nil },
			mockDevToolsCmd: func() ([]byte, error) { return []byte("DevTools Mode: INVALID"), nil },
			expectedCCMode:  attest.GPUDeviceCCMode_ON,
			wantErr:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			ccMode, err := QueryCCMode(tt.mockCCModeCmd, tt.mockDevToolsCmd)
			if (err != nil) != tt.wantErr {
				t.Errorf("QueryCCMode() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.errSubstr) {
				t.Errorf("QueryCCMode() error message %s is expected to contain %s", err.Error(), tt.errSubstr)
			}
			if ccMode != tt.expectedCCMode {
				t.Errorf("QueryCCMode() got = %v, want %v", ccMode, tt.expectedCCMode)
			}
		})
	}
}

func TestIsConfidentialComputeSupported(t *testing.T) {

	tests := []struct {
		name      string
		gpuType   deviceinfo.GPUType
		supported []deviceinfo.GPUType
		wantErr   bool
		errSubstr string
	}{
		{
			name:      "Supported GPU",
			gpuType:   deviceinfo.H100,
			supported: []deviceinfo.GPUType{deviceinfo.H100, deviceinfo.A100_40GB, deviceinfo.A100_80GB},
			wantErr:   false,
		},
		{
			name:      "Not supported GPU",
			gpuType:   deviceinfo.T4,
			supported: []deviceinfo.GPUType{deviceinfo.H100, deviceinfo.A100_40GB, deviceinfo.A100_80GB},
			wantErr:   true,
			errSubstr: "unsupported confidential GPU type",
		},
		{
			name:      "GPU with closed source kernel modules",
			gpuType:   deviceinfo.P100,
			supported: []deviceinfo.GPUType{deviceinfo.H100, deviceinfo.A100_40GB, deviceinfo.A100_80GB},
			wantErr:   true,
			errSubstr: "open sourced kernel modules are not supported for GPU type",
		},
		{
			name:      "Empty supported list",
			gpuType:   deviceinfo.H100,
			supported: []deviceinfo.GPUType{},
			wantErr:   true,
			errSubstr: "unsupported confidential GPU type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := isConfidentialComputeSupported(tt.gpuType, tt.supported)
			if (err != nil) != tt.wantErr {
				t.Errorf("isConfidentialComputeSupported() error = %v, want error = %v", err, tt.wantErr)
			}

			if tt.wantErr && !strings.Contains(err.Error(), tt.errSubstr) {
				t.Errorf("isConfidentialComputeSupported() error message %s is expected to contain %s", err.Error(), tt.errSubstr)
			}
		})
	}
}
