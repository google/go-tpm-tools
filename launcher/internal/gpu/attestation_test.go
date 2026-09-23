package gpu

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"cos.googlesource.com/cos/tools.git/src/cmd/cos_gpu_installer/deviceinfo"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-nvattest-tools/client"
	nvattestpb "github.com/google/go-nvattest-tools/proto/nvattest"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	attestationpb "github.com/GoogleCloudPlatform/confidential-space/server/proto/gen/attestation"
)

type fakeGpuQuoteProvider struct {
	quote *nvattestpb.GpuAttestationQuote
	err   error
}

func (f *fakeGpuQuoteProvider) CollectGpuEvidence(_ [32]byte) (*nvattestpb.GpuAttestationQuote, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.quote, nil
}

func validDevInfo(uuid, vbios, driver string, arch nvattestpb.GpuArchitectureType) *nvattestpb.GpuInfo {
	return &nvattestpb.GpuInfo{
		Uuid:                        uuid,
		VbiosVersion:                vbios,
		DriverVersion:               driver,
		GpuArchitecture:             arch,
		AttestationReport:           []byte("fake-report-bytes"),
		AttestationCertificateChain: []byte("fake-cert-chain-bytes"),
	}
}

func TestCollectAttestationEvidence(t *testing.T) {
	testCases := []struct {
		name       string
		nonce      []byte
		gpuType    deviceinfo.GPUType
		provider   client.GpuQuoteProvider
		wantPass   bool
		wantErrStr string
		wantSPT    bool
		wantMPT    bool
		wantArch   attestationpb.GpuArchitectureType
	}{
		{
			name:    "success w/ H100 SPT",
			nonce:   []byte("nonce-h100"),
			gpuType: deviceinfo.H100,
			provider: &fakeGpuQuoteProvider{
				quote: &nvattestpb.GpuAttestationQuote{
					GpuInfos: []*nvattestpb.GpuInfo{
						validDevInfo("gpu-h100-0", "vbios-h100", "550.54.14", nvattestpb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER),
					},
				},
			},
			wantPass: true,
			wantSPT:  true,
			wantArch: attestationpb.GpuArchitectureType_GPU_ARCHITECTURE_TYPE_HOPPER,
		},
		{
			name:    "success w/ RTX PRO 6000 SPT",
			nonce:   []byte("nonce-rtx"),
			gpuType: deviceinfo.RTX_PRO_6000,
			provider: &fakeGpuQuoteProvider{
				quote: &nvattestpb.GpuAttestationQuote{
					GpuInfos: []*nvattestpb.GpuInfo{
						validDevInfo("gpu-rtx-0", "vbios-rtx", "550.54.14", nvattestpb.GpuArchitectureType_GPU_ARCHITECTURE_BLACKWELL),
					},
				},
			},
			wantPass: true,
			wantSPT:  true,
			wantArch: attestationpb.GpuArchitectureType_GPU_ARCHITECTURE_TYPE_BLACKWELL,
		},
		{
			name:    "success w/ B200 single GPU SPT",
			nonce:   []byte("nonce-b200-single"),
			gpuType: deviceinfo.B200,
			provider: &fakeGpuQuoteProvider{
				quote: &nvattestpb.GpuAttestationQuote{
					GpuInfos: []*nvattestpb.GpuInfo{
						validDevInfo("gpu-b200-0", "vbios-b200", "550.54.14", nvattestpb.GpuArchitectureType_GPU_ARCHITECTURE_BLACKWELL),
					},
				},
			},
			wantPass: true,
			wantSPT:  true,
			wantArch: attestationpb.GpuArchitectureType_GPU_ARCHITECTURE_TYPE_BLACKWELL,
		},
		{
			name:    "success w/ B200 multi-GPU MPT",
			nonce:   []byte("nonce-b200-multi"),
			gpuType: deviceinfo.B200,
			provider: &fakeGpuQuoteProvider{
				quote: &nvattestpb.GpuAttestationQuote{
					GpuInfos: []*nvattestpb.GpuInfo{
						validDevInfo("gpu-b200-0", "vbios-b200-0", "550.54.14", nvattestpb.GpuArchitectureType_GPU_ARCHITECTURE_BLACKWELL),
						validDevInfo("gpu-b200-1", "vbios-b200-1", "550.54.14", nvattestpb.GpuArchitectureType_GPU_ARCHITECTURE_BLACKWELL),
					},
				},
			},
			wantPass: true,
			wantMPT:  true,
			wantArch: attestationpb.GpuArchitectureType_GPU_ARCHITECTURE_TYPE_BLACKWELL,
		},
		{
			name:    "failed due to multiple GPUs on H100",
			nonce:   []byte("nonce"),
			gpuType: deviceinfo.H100,
			provider: &fakeGpuQuoteProvider{
				quote: &nvattestpb.GpuAttestationQuote{
					GpuInfos: []*nvattestpb.GpuInfo{
						validDevInfo("gpu-0", "vbios-0", "550.54.14", nvattestpb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER),
						validDevInfo("gpu-1", "vbios-1", "550.54.14", nvattestpb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER),
					},
				},
			},
			wantPass:   false,
			wantErrStr: "unsupported GPU attestation",
		},
		{
			name:    "failed due to multiple GPUs on RTX PRO 6000",
			nonce:   []byte("nonce"),
			gpuType: deviceinfo.RTX_PRO_6000,
			provider: &fakeGpuQuoteProvider{
				quote: &nvattestpb.GpuAttestationQuote{
					GpuInfos: []*nvattestpb.GpuInfo{
						validDevInfo("gpu-0", "vbios-0", "550.54.14", nvattestpb.GpuArchitectureType_GPU_ARCHITECTURE_BLACKWELL),
						validDevInfo("gpu-1", "vbios-1", "550.54.14", nvattestpb.GpuArchitectureType_GPU_ARCHITECTURE_BLACKWELL),
					},
				},
			},
			wantPass:   false,
			wantErrStr: "unsupported GPU attestation",
		},
		{
			name:    "failed due to unsupported GPU attestation type (Others)",
			nonce:   []byte("nonce"),
			gpuType: deviceinfo.Others,
			provider: &fakeGpuQuoteProvider{
				quote: &nvattestpb.GpuAttestationQuote{
					GpuInfos: []*nvattestpb.GpuInfo{
						validDevInfo("gpu-0", "vbios-0", "550.54.14", nvattestpb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER),
					},
				},
			},
			wantPass:   false,
			wantErrStr: "unsupported GPU attestation",
		},
		{
			name:    "failed due to unsupported GPU attestation type (T4)",
			nonce:   []byte("nonce"),
			gpuType: deviceinfo.T4,
			provider: &fakeGpuQuoteProvider{
				quote: &nvattestpb.GpuAttestationQuote{
					GpuInfos: []*nvattestpb.GpuInfo{
						validDevInfo("gpu-0", "vbios-0", "550.54.14", nvattestpb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER),
					},
				},
			},
			wantPass:   false,
			wantErrStr: "unsupported GPU attestation",
		},
		{
			name:    "failed due to provider collection error",
			nonce:   []byte("nonce"),
			gpuType: deviceinfo.H100,
			provider: &fakeGpuQuoteProvider{
				err: errors.New("nvml hardware error"),
			},
			wantPass:   false,
			wantErrStr: "failed to collect GPU evidence: nvml hardware error",
		},
		{
			name:    "failed due to empty quote",
			nonce:   []byte("nonce"),
			gpuType: deviceinfo.H100,
			provider: &fakeGpuQuoteProvider{
				quote: &nvattestpb.GpuAttestationQuote{
					GpuInfos: nil,
				},
			},
			wantPass:   false,
			wantErrStr: "no GPU devices found in quote",
		},
		// Per-device error checks requested to ensure visibility into what failed for each device:
		{
			name:    "failed due to empty UUID",
			nonce:   []byte("nonce"),
			gpuType: deviceinfo.H100,
			provider: &fakeGpuQuoteProvider{
				quote: &nvattestpb.GpuAttestationQuote{
					GpuInfos: []*nvattestpb.GpuInfo{
						validDevInfo("", "vbios-0", "550.54.14", nvattestpb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER),
					},
				},
			},
			wantPass:   false,
			wantErrStr: "failed to get GPU device UUID: empty UUID at index 0",
		},
		{
			name:    "failed due to empty driver version",
			nonce:   []byte("nonce"),
			gpuType: deviceinfo.H100,
			provider: &fakeGpuQuoteProvider{
				quote: &nvattestpb.GpuAttestationQuote{
					GpuInfos: []*nvattestpb.GpuInfo{
						validDevInfo("gpu-test-0", "vbios-0", "", nvattestpb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER),
					},
				},
			},
			wantPass:   false,
			wantErrStr: "failed to get GPU driver version for GPU gpu-test-0 at index 0",
		},
		{
			name:    "failed due to empty VBIOS version",
			nonce:   []byte("nonce"),
			gpuType: deviceinfo.H100,
			provider: &fakeGpuQuoteProvider{
				quote: &nvattestpb.GpuAttestationQuote{
					GpuInfos: []*nvattestpb.GpuInfo{
						validDevInfo("gpu-test-0", "", "550.54.14", nvattestpb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER),
					},
				},
			},
			wantPass:   false,
			wantErrStr: "failed to get GPU VBIOS version for GPU gpu-test-0 at index 0",
		},
		{
			name:    "failed due to unspecified GPU architecture",
			nonce:   []byte("nonce"),
			gpuType: deviceinfo.H100,
			provider: &fakeGpuQuoteProvider{
				quote: &nvattestpb.GpuAttestationQuote{
					GpuInfos: []*nvattestpb.GpuInfo{
						validDevInfo("gpu-test-0", "vbios-0", "550.54.14", nvattestpb.GpuArchitectureType_GPU_ARCHITECTURE_UNSPECIFIED),
					},
				},
			},
			wantPass:   false,
			wantErrStr: "unsupported or unspecified GPU architecture",
		},
		{
			name:    "failed due to empty attestation report",
			nonce:   []byte("nonce"),
			gpuType: deviceinfo.H100,
			provider: &fakeGpuQuoteProvider{
				quote: &nvattestpb.GpuAttestationQuote{
					GpuInfos: []*nvattestpb.GpuInfo{
						{
							Uuid:                        "gpu-test-0",
							VbiosVersion:                "vbios-0",
							DriverVersion:               "550.54.14",
							GpuArchitecture:             nvattestpb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
							AttestationReport:           nil,
							AttestationCertificateChain: []byte("fake-cert-chain"),
						},
					},
				},
			},
			wantPass:   false,
			wantErrStr: "failed to get GPU attestation report for GPU gpu-test-0 at index 0: empty report",
		},
		{
			name:    "failed due to empty certificate chain",
			nonce:   []byte("nonce"),
			gpuType: deviceinfo.H100,
			provider: &fakeGpuQuoteProvider{
				quote: &nvattestpb.GpuAttestationQuote{
					GpuInfos: []*nvattestpb.GpuInfo{
						{
							Uuid:                        "gpu-test-0",
							VbiosVersion:                "vbios-0",
							DriverVersion:               "550.54.14",
							GpuArchitecture:             nvattestpb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
							AttestationReport:           []byte("fake-report"),
							AttestationCertificateChain: nil,
						},
					},
				},
			},
			wantPass:   false,
			wantErrStr: "failed to get GPU certificate chain for GPU gpu-test-0 at index 0: empty certificate chain",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fn := &getGpuTypeInfo
			getGpuTypeInfo = func(string) (deviceinfo.GPUType, error) {
				return tc.gpuType, nil
			}
			t.Cleanup(func() { getGpuTypeInfo = *fn })

			attester := &NvidiaAttester{}
			attesation, err := attester.collectAttestationEvidence(tc.provider, tc.nonce)
			if gotPass := (err == nil); gotPass != tc.wantPass {
				t.Fatalf("CollectAttestationEvidence() error = %v, wantPass = %v", err, tc.wantPass)
			}
			if !tc.wantPass {
				if tc.wantErrStr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErrStr)) {
					t.Errorf("error = %q, want error containing %q", err, tc.wantErrStr)
				}
				return
			}

			// Validate SHA-256 hashed challenge nonce
			expectedNonce := sha256.Sum256(tc.nonce)
			if !bytes.Equal(attesation.GetNonce(), expectedNonce[:]) {
				t.Errorf("attesation.GetNonce() = %x, want %x", attesation.GetNonce(), expectedNonce)
			}

			// Validate SPT vs MPT feature structure and fields
			if tc.wantSPT {
				sptReport, ok := attesation.CcFeature.(*attestationpb.NvidiaAttestationReport_Spt)
				if !ok {
					t.Fatalf("attesation.CcFeature is %T, want *attestationpb.NvidiaAttestationReport_Spt", attesation.CcFeature)
				}
				quote := sptReport.Spt.GetGpuQuote()
				if quote == nil {
					t.Fatal("spt.GpuQuote is nil")
				}
				fakeDev := tc.provider.(*fakeGpuQuoteProvider).quote.GpuInfos[0]
				if quote.GetUuid() != fakeDev.GetUuid() {
					t.Errorf("quote.GetUuid() = %v, want %v", quote.GetUuid(), fakeDev.GetUuid())
				}
				if quote.GetVbiosVersion() != fakeDev.GetVbiosVersion() {
					t.Errorf("quote.GetVbiosVersion() = %v, want %v", quote.GetVbiosVersion(), fakeDev.GetVbiosVersion())
				}
				if quote.GetDriverVersion() != fakeDev.GetDriverVersion() {
					t.Errorf("quote.GetDriverVersion() = %v, want %v", quote.GetDriverVersion(), fakeDev.GetDriverVersion())
				}
				if quote.GetGpuArchitectureType() != tc.wantArch {
					t.Errorf("quote.GetGpuArchitectureType() = %v, want %v", quote.GetGpuArchitectureType(), tc.wantArch)
				}
				if len(quote.GetAttestationReport()) == 0 {
					t.Error("quote.GetAttestationReport() is empty")
				}
				if len(quote.GetAttestationCertificateChain()) == 0 {
					t.Error("quote.GetAttestationCertificateChain() is empty")
				}
			}

			if tc.wantMPT {
				mptReport, ok := attesation.CcFeature.(*attestationpb.NvidiaAttestationReport_Mpt)
				if !ok {
					t.Fatalf("attesation.CcFeature is %T, want *attestationpb.NvidiaAttestationReport_Mpt", attesation.CcFeature)
				}
				quotes := mptReport.Mpt.GetGpuQuotes()
				fakeDevs := tc.provider.(*fakeGpuQuoteProvider).quote.GpuInfos
				if len(quotes) != len(fakeDevs) {
					t.Fatalf("len(mpt.GpuQuotes) = %d, want %d", len(quotes), len(fakeDevs))
				}
				for i, dev := range fakeDevs {
					q := quotes[i]
					if q.GetUuid() != dev.GetUuid() {
						t.Errorf("quotes[%d].GetUuid() = %v, want %v", i, q.GetUuid(), dev.GetUuid())
					}
					if q.GetVbiosVersion() != dev.GetVbiosVersion() {
						t.Errorf("quotes[%d].GetVbiosVersion() = %v, want %v", i, q.GetVbiosVersion(), dev.GetVbiosVersion())
					}
					if q.GetGpuArchitectureType() != tc.wantArch {
						t.Errorf("quotes[%d].GetGpuArchitectureType() = %v, want %v", i, q.GetGpuArchitectureType(), tc.wantArch)
					}
					if len(q.GetAttestationReport()) == 0 {
						t.Errorf("quotes[%d].GetAttestationReport() is empty", i)
					}
					if len(q.GetAttestationCertificateChain()) == 0 {
						t.Errorf("quotes[%d].GetAttestationCertificateChain() is empty", i)
					}
				}
			}

			// Wire format guardrail: verify protobuf serialization & deserialization round-trip
			marshaled, err := proto.Marshal(attesation)
			if err != nil {
				t.Fatalf("proto.Marshal(attesation) failed: %v", err)
			}
			unmarshaled := &attestationpb.NvidiaAttestationReport{}
			if err := proto.Unmarshal(marshaled, unmarshaled); err != nil {
				t.Fatalf("proto.Unmarshal(marshaled) failed: %v", err)
			}
			if diff := cmp.Diff(attesation, unmarshaled, protocmp.Transform()); diff != "" {
				t.Errorf("proto round-trip mismatch (-want +got):\n%s", diff)
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
			name: "Unsupported attestation type (H100 with multiple GPUs)",
			gpuInfos: []*attestationpb.GpuInfo{
				{Uuid: "gpu-0"},
				{Uuid: "gpu-1"},
			},
			gpuType: deviceinfo.H100,
			want:    UNSUPPORTED,
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
		{
			name: "SPT attestation type (RTX PRO 6000)",
			gpuInfos: []*attestationpb.GpuInfo{
				{Uuid: "gpu-0"},
			},
			gpuType: deviceinfo.RTX_PRO_6000,
			want:    SPT,
		},
		{
			name: "Unsupported attestation type (RTX PRO 6000 with multiple GPUs)",
			gpuInfos: []*attestationpb.GpuInfo{
				{Uuid: "gpu-0"},
				{Uuid: "gpu-1"},
			},
			gpuType: deviceinfo.RTX_PRO_6000,
			want:    UNSUPPORTED,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fn := &getGpuTypeInfo
			getGpuTypeInfo = func(string) (deviceinfo.GPUType, error) {
				return tc.gpuType, nil
			}
			t.Cleanup(func() { getGpuTypeInfo = *fn })

			if got := determineAttestationType(tc.gpuInfos); got != tc.want {
				t.Errorf("determineAttestationType() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestConvertGPUArchToPB(t *testing.T) {
	testCases := []struct {
		arch     nvattestpb.GpuArchitectureType
		wantArch attestationpb.GpuArchitectureType
	}{
		{
			arch:     nvattestpb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER,
			wantArch: attestationpb.GpuArchitectureType_GPU_ARCHITECTURE_TYPE_HOPPER,
		},
		{
			arch:     nvattestpb.GpuArchitectureType_GPU_ARCHITECTURE_BLACKWELL,
			wantArch: attestationpb.GpuArchitectureType_GPU_ARCHITECTURE_TYPE_BLACKWELL,
		},
		{
			arch:     nvattestpb.GpuArchitectureType_GPU_ARCHITECTURE_UNSPECIFIED,
			wantArch: attestationpb.GpuArchitectureType_GPU_ARCHITECTURE_TYPE_UNSPECIFIED,
		},
		{
			arch:     nvattestpb.GpuArchitectureType_GPU_ARCHITECTURE_UNKNOWN,
			wantArch: attestationpb.GpuArchitectureType_GPU_ARCHITECTURE_TYPE_UNSPECIFIED,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.arch.String(), func(t *testing.T) {
			if got := convertGPUArchToPB(tc.arch); got != tc.wantArch {
				t.Errorf("convertGPUArchToPB(%v) = %v, want %v", tc.arch, got, tc.wantArch)
			}
		})
	}
}

func TestNewNvidiaAttester(t *testing.T) {
	if got := NewNvidiaAttester(false); got != nil {
		t.Errorf("NewNvidiaAttester(false) = %v, want nil", got)
	}

	got := NewNvidiaAttester(true)
	if got == nil {
		t.Fatalf("NewNvidiaAttester(true) = nil, want non-nil *NvidiaAttester")
	}

	// Verify *NvidiaAttester satisfies Attester interface
	var _ Attester = got
}

func TestAttestWithQuoteProvider(t *testing.T) {
	fn := &getGpuTypeInfo
	getGpuTypeInfo = func(string) (deviceinfo.GPUType, error) {
		return deviceinfo.H100, nil
	}
	t.Cleanup(func() { getGpuTypeInfo = *fn })

	fakeProvider := &fakeGpuQuoteProvider{
		quote: &nvattestpb.GpuAttestationQuote{
			GpuInfos: []*nvattestpb.GpuInfo{
				validDevInfo("gpu-provider-test-0", "vbios-test", "550.54.14", nvattestpb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER),
			},
		},
	}

	attester := &NvidiaAttester{
		quoteProvider: fakeProvider,
	}

	challengeNonce := []byte("challenge-nonce-12345")
	evidence, err := attester.Attest(challengeNonce)
	if err != nil {
		t.Fatalf("Attest() failed: %v", err)
	}

	report, ok := evidence.(*attestationpb.NvidiaAttestationReport)
	if !ok {
		t.Fatalf("Attest() returned %T, want *attestationpb.NvidiaAttestationReport", evidence)
	}

	expectedNonce := sha256.Sum256(challengeNonce)
	if !bytes.Equal(report.GetNonce(), expectedNonce[:]) {
		t.Errorf("report.GetNonce() = %x, want %x", report.GetNonce(), expectedNonce)
	}

	quote := report.GetSpt().GetGpuQuote()
	if quote == nil {
		t.Fatal("report.GetSpt().GetGpuQuote() is nil")
	}
	if quote.GetUuid() != "gpu-provider-test-0" {
		t.Errorf("quote.GetUuid() = %v, want %v", quote.GetUuid(), "gpu-provider-test-0")
	}

	// Verify nil attester error handling
	var nilAttester *NvidiaAttester
	if _, err := nilAttester.Attest(challengeNonce); err == nil {
		t.Error("nilAttester.Attest() expected error, got nil")
	}
	if err := nilAttester.EnableReadyState(); err == nil {
		t.Error("nilAttester.EnableReadyState() expected error, got nil")
	}
}
