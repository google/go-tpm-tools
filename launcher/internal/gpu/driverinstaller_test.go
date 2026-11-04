package gpu

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"cos.googlesource.com/cos/tools.git/src/cmd/cos_gpu_installer/deviceinfo"
	"github.com/containerd/containerd"
)

var errTransportCalled = errors.New("transport called")

// recordingTransport records requested hosts and fails all requests to prevent network calls.
type recordingTransport struct {
	hosts []string
}

func (rt *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.hosts = append(rt.hosts, req.URL.Host)
	return nil, errTransportCalled
}

func TestInstallerPullOptsUseRegistryClient(t *testing.T) {
	transport := &recordingTransport{}
	rc := &containerd.RemoteContext{}
	for _, opt := range installerPullOpts(&http.Client{Transport: transport}) {
		if err := opt(nil, rc); err != nil {
			t.Fatalf("RemoteOpt failed: %v", err)
		}
	}

	rc.Resolver.Resolve(t.Context(), InstallerImageRef)

	wantHosts := []string{"us.gcr.io"}
	if !slices.Equal(transport.hosts, wantHosts) {
		t.Errorf("installerPullOpts() registry client request hosts = %v, want %v", transport.hosts, wantHosts)
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
