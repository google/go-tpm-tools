package gpu

import (
	"crypto/sha256"
	"fmt"

	"cos.googlesource.com/cos/tools.git/src/cmd/cos_gpu_installer/deviceinfo"
	"github.com/google/go-nvattest-tools/client"
	nvattestpb "github.com/google/go-nvattest-tools/proto/nvattest"

	attestationpb "github.com/GoogleCloudPlatform/confidential-space/server/proto/gen/attestation"
	"github.com/google/go-tpm-tools/agent/device"
	"github.com/google/go-tpm-tools/proto/attest"
)

type attestationType int

const (
	// UNSUPPORTED indicates unsupported GPU attestation type like PPCIE.
	UNSUPPORTED attestationType = iota
	// SPT indicates Nvidia's single GPU passthrough attestation
	SPT
	// MPT indicates Nvidia's multi GPU secure passthrough attestation
	MPT
)

// Stub this func for testing purpose.
var getGpuTypeInfo = deviceinfo.GetGPUTypeInfo

// Attester defines the interface for GPU attestation.
type Attester interface {
	device.ROT
	device.ReadyStateEnabler
}

// NvidiaAttester is responsible for collecting GPU attestation.
type NvidiaAttester struct {
	quoteProvider client.GpuQuoteProvider
}

// NewNvidiaAttester returns a new NvidiaAttester if installGpuDriver is true, otherwise nil.
func NewNvidiaAttester(installGpuDriver bool) *NvidiaAttester {
	if !installGpuDriver {
		return nil
	}
	return &NvidiaAttester{
		quoteProvider: &client.LinuxGpuQuoteProvider{},
	}
}

// Vendor returns the device ROT vendor type for Nvidia GPU.
func (a *NvidiaAttester) Vendor() device.Vendor {
	return device.NvidiaGPU
}

// Attest returns a GPU attestation.
func (a *NvidiaAttester) Attest(nonce []byte) (any, error) {
	if a == nil {
		return nil, fmt.Errorf("nil Nvidia attester")
	}
	provider := a.quoteProvider
	if provider == nil {
		provider = &client.LinuxGpuQuoteProvider{}
	}
	gpuAttestation, err := a.collectAttestationEvidence(provider, nonce)
	if err != nil {
		return nil, err
	}
	return gpuAttestation, nil
}

// EnableReadyState checks the Confidential Computing mode and transitions the GPU to a READY state if CC is enabled.
func (a *NvidiaAttester) EnableReadyState() error {
	if a == nil {
		return fmt.Errorf("nil Nvidia attester")
	}

	ccModeCmd := NvidiaSmiOutputFunc("conf-compute", "-f")
	devToolsCmd := NvidiaSmiOutputFunc("conf-compute", "-d")

	ccEnabled, err := QueryCCMode(ccModeCmd, devToolsCmd)
	if err != nil {
		return fmt.Errorf("failed to check confidential compute mode status: %v", err)
	}

	// Explicitly need to set the GPU state to READY for GPUs with confidential compute mode ON.
	if ccEnabled == attest.GPUDeviceCCMode_ON || ccEnabled == attest.GPUDeviceCCMode_DEVTOOLS {
		setGPUStateCmd := NvidiaSmiOutputFunc("conf-compute", "-srs", "1")
		if err := setGPUStateToReady(setGPUStateCmd); err != nil {
			return fmt.Errorf("failed to set the GPU state to ready: %v", err)
		}
	}

	return nil
}

// collectAttestationEvidence assumes CC GPU devices are in place w/ driver support
// and will try to collect raw attestation evidence and convert it to known data models.
func (a *NvidiaAttester) collectAttestationEvidence(provider client.GpuQuoteProvider, nonce []byte) (*attestationpb.NvidiaAttestationReport, error) {
	if provider == nil {
		return nil, fmt.Errorf("nil GPU quote provider")
	}

	nvNonce := sha256.Sum256(nonce)
	quote, err := provider.CollectGpuEvidence(nvNonce)
	if err != nil {
		return nil, fmt.Errorf("failed to collect GPU evidence: %w", err)
	}

	if quote == nil || len(quote.GetGpuInfos()) == 0 {
		return nil, fmt.Errorf("no GPU devices found in quote")
	}

	var gpuInfos []*attestationpb.GpuInfo
	for i, devInfo := range quote.GetGpuInfos() {
		if devInfo == nil {
			return nil, fmt.Errorf("nil GPU device info at index %d", i)
		}

		uuid := devInfo.GetUuid()
		if uuid == "" {
			return nil, fmt.Errorf("failed to get GPU device UUID: empty UUID at index %d", i)
		}

		driverVersion := devInfo.GetDriverVersion()
		if driverVersion == "" {
			return nil, fmt.Errorf("failed to get GPU driver version for GPU %s at index %d", uuid, i)
		}

		vbiosVersion := devInfo.GetVbiosVersion()
		if vbiosVersion == "" {
			return nil, fmt.Errorf("failed to get GPU VBIOS version for GPU %s at index %d", uuid, i)
		}

		arch := convertGPUArchToPB(devInfo.GetGpuArchitecture())
		if arch == attestationpb.GpuArchitectureType_GPU_ARCHITECTURE_TYPE_UNSPECIFIED {
			return nil, fmt.Errorf("unsupported or unspecified GPU architecture %v for GPU %s at index %d", devInfo.GetGpuArchitecture(), uuid, i)
		}

		report := devInfo.GetAttestationReport()
		if len(report) == 0 {
			return nil, fmt.Errorf("failed to get GPU attestation report for GPU %s at index %d: empty report", uuid, i)
		}

		certChain := devInfo.GetAttestationCertificateChain()
		if len(certChain) == 0 {
			return nil, fmt.Errorf("failed to get GPU certificate chain for GPU %s at index %d: empty certificate chain", uuid, i)
		}

		gpuInfo := &attestationpb.GpuInfo{
			Uuid:                        uuid,
			DriverVersion:               driverVersion,
			VbiosVersion:                vbiosVersion,
			GpuArchitectureType:         arch,
			AttestationReport:           report,
			AttestationCertificateChain: certChain,
		}
		gpuInfos = append(gpuInfos, gpuInfo)
	}

	switch determineAttestationType(gpuInfos) {
	case SPT:
		return &attestationpb.NvidiaAttestationReport{
			CcFeature: &attestationpb.NvidiaAttestationReport_Spt{
				Spt: &attestationpb.NvidiaAttestationReport_SinglePassthroughAttestation{
					GpuQuote: gpuInfos[0],
				},
			},
			Nonce: nvNonce[:],
		}, nil
	case MPT:
		return &attestationpb.NvidiaAttestationReport{
			CcFeature: &attestationpb.NvidiaAttestationReport_Mpt{
				Mpt: &attestationpb.NvidiaAttestationReport_MultiGpuSecurePassthroughAttestation{
					GpuQuotes: gpuInfos,
				},
			},
			Nonce: nvNonce[:],
		}, nil
	default:
		return nil, fmt.Errorf("unsupported GPU attestation")
	}
}

// determineAttestationType auto-detects the GPU attestation type.
// The current implementations "guess" the attestation type.
// Further improvement should be made to parse GPU attestation report to get the actual attestation type.
func determineAttestationType(gpuInfos []*attestationpb.GpuInfo) attestationType {
	gpuType, _ := getGpuTypeInfo(PciDevicesDir)
	if gpuType != deviceinfo.H100 && gpuType != deviceinfo.B200 && gpuType != deviceinfo.RTX_PRO_6000 {
		return UNSUPPORTED
	}
	// H100 and RTX PRO 6000 can only support single GPU attestation in CS at the moment.
	if (gpuType == deviceinfo.H100 || gpuType == deviceinfo.RTX_PRO_6000) && len(gpuInfos) != 1 {
		return UNSUPPORTED
	}
	if gpuType == deviceinfo.B200 && len(gpuInfos) > 1 {
		return MPT
	}
	return SPT
}

func convertGPUArchToPB(arch nvattestpb.GpuArchitectureType) attestationpb.GpuArchitectureType {
	switch arch {
	case nvattestpb.GpuArchitectureType_GPU_ARCHITECTURE_HOPPER:
		return attestationpb.GpuArchitectureType_GPU_ARCHITECTURE_TYPE_HOPPER
	case nvattestpb.GpuArchitectureType_GPU_ARCHITECTURE_BLACKWELL:
		return attestationpb.GpuArchitectureType_GPU_ARCHITECTURE_TYPE_BLACKWELL
	default:
		return attestationpb.GpuArchitectureType_GPU_ARCHITECTURE_TYPE_UNSPECIFIED
	}
}
