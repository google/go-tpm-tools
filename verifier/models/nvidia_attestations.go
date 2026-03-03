package models

type NvidiaAttestation struct {
	CCFeature any
}

func (a *NvidiaAttestation) GetSpt() *NvidiaSinglePassthroughAttestation {
	if a != nil {
		if spt, ok := a.CCFeature.(*NvidiaSinglePassthroughAttestation); ok {
			return spt
		}
	}
	return nil
}

func (a *NvidiaAttestation) GetMpt() *NvidiaMultiGpuSecurePassthroughAttestation {
	if a != nil {
		if mpt, ok := a.CCFeature.(*NvidiaMultiGpuSecurePassthroughAttestation); ok {
			return mpt
		}
	}
	return nil
}

type NvidiaSinglePassthroughAttestation struct {
	GPUInfo GPUInfo
}

type NvidiaMultiGpuSecurePassthroughAttestation struct {
	GPUInfos []GPUInfo
}

type GPUInfo struct {
	UUID                        string // The UUID of the GPU device.
	DriverVersion               string // The driver version of the GPU.
	VBIOSVersion                string // The VBIOS version of the GPU.
	GPUArchitectureType         string // The architecture type of the GPU.
	AttestationCertificateChain []byte // The raw certificate chain for attestation.
	AttestationReport           []byte // The raw attestation report for the GPU.
}
