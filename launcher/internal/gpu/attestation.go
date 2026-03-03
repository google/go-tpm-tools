package gpu

import (
	"crypto/sha256"
	"fmt"

	"encoding/base64"

	"cos.googlesource.com/cos/tools.git/src/cmd/cos_gpu_installer/deviceinfo"
	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/gpu"
	"github.com/google/go-tpm-tools/verifier/models"
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

// NvidiaAttester is responsible for collecting GPU attestation.
type NvidiaAttester struct{}

// Attest returns a GPU attestation.
func (a *NvidiaAttester) Attest(nonce []byte) (any, error) {
	gpuAttestation, err := a.collectAttestationEvidence(&gpu.DefaultNVMLHandler{}, nonce)
	if err != nil {
		return nil, err
	}
	return gpuAttestation, nil
}

// collectAttestationEvidence assumes CC GPU devices are in place w/ driver support
// and will try to collect raw attestation evidence and convert it to known data models.
func (a *NvidiaAttester) collectAttestationEvidence(handler gpu.NvmlHandler, nonce []byte) (*models.NvidiaAttestation, error) {
	gpuAdmin, err := gpu.NewNvmlGPUAdmin(handler)
	if err != nil {
		return nil, fmt.Errorf("failed to create GPU admin: %v", err)
	}
	defer gpuAdmin.Shutdown()

	nvNonce := sha256.Sum256(nonce)
	deviceInfos, err := gpuAdmin.CollectEvidence(nvNonce[:])
	if err != nil {
		return nil, fmt.Errorf("failed to collect GPU evidence: %v", err)
	}

	var gpuInfos []models.GPUInfo
	for i, deviceInfo := range deviceInfos {
		device, ret := handler.DeviceGetHandleByIndex(i)
		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("failed to get GPU device: %v", nvml.ErrorString(ret))
		}
		uuid, ret := device.GetUUID()
		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("failed to get GPU device UUID: %v", nvml.ErrorString(ret))
		}

		vbiosVersion, ret := device.GetVbiosVersion()
		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("failed to get GPU VBIOS version: %v", nvml.ErrorString(ret))
		}

		driverVersion, ret := handler.SystemGetDriverVersion()
		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("failed to get GPU driver version: %v", nvml.ErrorString(ret))
		}

		base64PEM, err := deviceInfo.Certificate().EncodeBase64()
		if err != nil {
			return nil, fmt.Errorf("failed to encode GPU certificate chain: %v", err)
		}

		attestationCertChainData, err := base64.StdEncoding.DecodeString(base64PEM)
		if err != nil {
			return nil, fmt.Errorf("failed to decode GPU certificate chain: %v", err)
		}

		gpuInfo := models.GPUInfo{
			UUID:                        uuid,
			DriverVersion:               driverVersion,
			VBIOSVersion:                vbiosVersion,
			GPUArchitectureType:         deviceInfo.Arch(),
			AttestationReport:           deviceInfo.AttestationReport(),
			AttestationCertificateChain: attestationCertChainData,
		}
		gpuInfos = append(gpuInfos, gpuInfo)
	}

	switch determineAttestationType(gpuInfos) {
	case SPT:
		return &models.NvidiaAttestation{
			CCFeature: &models.NvidiaSinglePassthroughAttestation{
				GPUInfo: gpuInfos[0],
			},
		}, nil
	case MPT:
		return &models.NvidiaAttestation{
			CCFeature: &models.NvidiaMultiGpuSecurePassthroughAttestation{
				GPUInfos: gpuInfos,
			},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported GPU attestation")
	}
}

// determineAttesationType auto-detects the GPU attestation type.
// The current implementations "guess" the attestation type.
// Further improvement should be made to parse GPU attesation report to get the actual attestation type.
func determineAttestationType(gpuInfos []models.GPUInfo) attestationType {
	gpuType, _ := getGpuTypeInfo()
	if gpuType != deviceinfo.H100 && gpuType != deviceinfo.B200 {
		return UNSUPPORTED
	}
	if gpuType == deviceinfo.B200 && len(gpuInfos) > 1 {
		return MPT
	}
	return SPT
}
