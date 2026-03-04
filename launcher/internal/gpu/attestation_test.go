package gpu

import (
	"testing"

	"cos.googlesource.com/cos/tools.git/src/cmd/cos_gpu_installer/deviceinfo"
	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/gpu"

	attestationpb "github.com/GoogleCloudPlatform/confidential-space/server/proto/gen/attestation"
)

func TestCollectAttestationEvidence(t *testing.T) {
	handler := &gpu.NVMLHandlerMock{}

	testCases := []struct {
		name     string
		nonce    []byte
		gpuType  deviceinfo.GPUType
		wantPass bool
		wantSPT  bool
		wantMPT  bool
	}{
		{
			name:     "success w/ H100 SPT",
			nonce:    []byte("nonce"),
			gpuType:  deviceinfo.H100,
			wantPass: true,
			wantSPT:  true,
		},
		// Comment out since the mock NVML handler will not return multiple GPU attestations
		// {
		// 	name: "success w/ B200",
		// 	nonce: []byte("nonce"),
		// 	B200: false,
		// 	H100: true,
		// 	wantPass: true,
		//  wantMPT: true,
		// },
		{
			name:     "failed due to unsupported GPU attestation type",
			nonce:    []byte("nonce"),
			gpuType:  deviceinfo.Others,
			wantPass: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fn := &getGpuTypeInfo
			getGpuTypeInfo = func() (deviceinfo.GPUType, error) {
				return tc.gpuType, nil
			}
			// Restore to original func after testing
			t.Cleanup(func() { getGpuTypeInfo = *fn })

			attester := &NvidiaAttester{}
			attesation, err := attester.collectAttestationEvidence(handler, tc.nonce)
			if gotPass := (err == nil); gotPass != tc.wantPass {
				t.Errorf("CollectAttestationEvidence() = %v, want %v", gotPass, tc.wantPass)
			}
			if tc.wantPass {
				if tc.wantSPT {
					if _, ok := attesation.CcFeature.(*attestationpb.NvidiaAttestationReport_Spt); !ok {
						t.Errorf("CollectAttestationEvidence() = %v, want %v", attesation.CcFeature, &attestationpb.NvidiaAttestationReport_Spt{})
					}
				}
			}
		})
	}
}

func TestDetermineAttestationType(t *testing.T) {
	testCases := []struct {
		name     string
		gpuInfos []*attestationpb.GpuInfo
		gpuType  deviceinfo.GPUType
		want     attestationType
	}{
		{
			name: "UNSUPPORTED GPU type",
			gpuInfos: []*attestationpb.GpuInfo{
				{Uuid: "gpu-0"},
			},
			gpuType: deviceinfo.Others,
			want:    UNSUPPORTED,
		},
		{
			name: "SPT attestation type (H100)",
			gpuInfos: []*attestationpb.GpuInfo{
				{Uuid: "gpu-0"},
			},
			gpuType: deviceinfo.H100,
			want:    SPT,
		},
		{
			name: "SPT attestation type (B200 with single GPU)",
			gpuInfos: []*attestationpb.GpuInfo{
				{Uuid: "gpu-0"},
			},
			gpuType: deviceinfo.B200,
			want:    SPT,
		},
		{
			name: "MPT attestation type (B200 with multiple GPUs)",
			gpuInfos: []*attestationpb.GpuInfo{
				{Uuid: "gpu-0"},
				{Uuid: "gpu-1"},
			},
			gpuType: deviceinfo.B200,
			want:    MPT,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fn := &getGpuTypeInfo
			getGpuTypeInfo = func() (deviceinfo.GPUType, error) {
				return tc.gpuType, nil
			}
			// Restore to original func after testing
			t.Cleanup(func() { getGpuTypeInfo = *fn })

			if got := determineAttestationType(tc.gpuInfos); got != tc.want {
				t.Errorf("determineAttestationType() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestConvertGPUArchToPB(t *testing.T) {
	testCases := []struct {
		arch     string
		wantArch attestationpb.GpuArchitectureType
	}{
		{
			arch:     "HOPPER",
			wantArch: attestationpb.GpuArchitectureType_GPU_ARCHITECTURE_TYPE_HOPPER,
		},
		{
			arch:     "BLACKWELL",
			wantArch: attestationpb.GpuArchitectureType_GPU_ARCHITECTURE_TYPE_BLACKWELL,
		},
		{
			arch:     "UNSPECIFIED",
			wantArch: attestationpb.GpuArchitectureType_GPU_ARCHITECTURE_TYPE_UNSPECIFIED,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.arch, func(t *testing.T) {
			if got := convertGPUArchToPB(tc.arch); got != tc.wantArch {
				t.Errorf("convertGPUArchToPB() = %v, want %v", got, tc.wantArch)
			}
		})
	}

}
