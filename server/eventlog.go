package server

import (
	"bytes"
	"errors"
	"fmt"

	gecel "github.com/google/go-eventlog/cel"
	"github.com/google/go-eventlog/extract"
	gepb "github.com/google/go-eventlog/proto/state"
	"github.com/google/go-eventlog/register"
	"github.com/google/go-eventlog/tpmeventlog"
	"github.com/google/go-tpm-tools/cel"
	pb "github.com/google/go-tpm-tools/proto/attest"
	tpmpb "github.com/google/go-tpm-tools/proto/tpm"
)

// parsePCClientEventLog parses a raw event log and replays the parsed event
// log against the given PCR values. It returns the corresponding MachineState
// containing the events verified by particular PCR indexes/digests. It returns
// an error if the replay for any PCR index does not match the provided value.
//
// The returned MachineState may be a partial MachineState where fields can be
// the zero value. In this case, an error of type MachineStateError will be
// returned. Callers can inspect individual parsing errors by examining
// `MachineStateError.Errors`.
//
// It is the caller's responsibility to ensure that the passed PCR values can be
// trusted. Users can establish trust in PCR values by either calling
// client.ReadPCRs() themselves or by verifying the values via a PCR quote.
//
// Return a grouped error for backward compatibility.
func parsePCClientEventLog(rawEventLog []byte, pcrs *tpmpb.PCRs, opts VerifyOpts) (*pb.MachineState, error) {
	extractOpts := extract.Opts{
		AllowEmptySBVar:               opts.AllowEmptySBVar,
		AllowEFIAppBeforeCallingEvent: opts.AllowEFIAppBeforeCallingEvent,
	}
	switch opts.Loader {
	case GRUB:
		extractOpts.Loader = extract.GRUB
	case UnsupportedLoader:
		extractOpts.Loader = extract.UnsupportedLoader
	default:
		return nil, createGroupedError("", []error{fmt.Errorf("unsupported bootloader option for event log extraction: %v", opts.Loader)})
	}

	tcghashalgo := gepb.HashAlgo(pcrs.GetHash())
	cryptoHashAlg, err := tcghashalgo.CryptoHash()
	if err != nil {
		return nil, createGroupedError("", []error{err})
	}

	pcrRegs := make([]register.PCR, 0)

	for pcrIndex, digest := range pcrs.GetPcrs() {
		pcrRegs = append(pcrRegs, register.PCR{
			Index:     int(pcrIndex),
			Digest:    digest,
			DigestAlg: cryptoHashAlg,
		})
	}

	pcrbank := register.PCRBank{
		TCGHashAlgo: tcghashalgo,
		PCRs:        pcrRegs,
	}

	tpmfirmwarestate, err := tpmeventlog.ReplayAndExtract(rawEventLog, pcrbank, extractOpts)
	if err != nil {
		return nil, err
	}

	machineState, err := ConvertToMachineState(tpmfirmwarestate)
	if err != nil {
		return nil, err
	}
	return machineState, nil
}

// ConvertToMachineState converts a go-eventlog FirmwareLogState to a MachineState.
func ConvertToMachineState(tpmfirmwarestate *gepb.FirmwareLogState) (*pb.MachineState, error) {
	var platformstate *pb.PlatformState
	if tpmfirmwarestate.GetPlatform() != nil {
		platformstate = &pb.PlatformState{}
		switch tpmfirmwarestate.GetPlatform().GetTechnology() {
		case gepb.GCEConfidentialTechnology_AMD_SEV:
			platformstate.Technology = pb.GCEConfidentialTechnology_AMD_SEV
		case gepb.GCEConfidentialTechnology_AMD_SEV_ES:
			platformstate.Technology = pb.GCEConfidentialTechnology_AMD_SEV_ES
		case gepb.GCEConfidentialTechnology_INTEL_TDX:
			platformstate.Technology = pb.GCEConfidentialTechnology_INTEL_TDX
		case gepb.GCEConfidentialTechnology_AMD_SEV_SNP:
			platformstate.Technology = pb.GCEConfidentialTechnology_AMD_SEV_SNP
		case gepb.GCEConfidentialTechnology_NONE:
			platformstate.Technology = pb.GCEConfidentialTechnology_NONE
		default:
			return nil, fmt.Errorf("unsupported GCE confidential technology: %v", tpmfirmwarestate.GetPlatform().GetTechnology())
		}
		switch fw := tpmfirmwarestate.GetPlatform().GetFirmware().(type) {
		case *gepb.PlatformState_GceVersion:
			platformstate.Firmware = &pb.PlatformState_GceVersion{GceVersion: fw.GceVersion}
		case *gepb.PlatformState_ScrtmVersionId:
			platformstate.Firmware = &pb.PlatformState_ScrtmVersionId{ScrtmVersionId: fw.ScrtmVersionId}
		}
	}

	var secureBootState *pb.SecureBootState
	if tpmfirmwarestate.GetSecureBoot() != nil {
		secureBootState = &pb.SecureBootState{
			Enabled: tpmfirmwarestate.GetSecureBoot().GetEnabled(),
			Db:      convertToPbDatabase(tpmfirmwarestate.GetSecureBoot().GetDb()),
			Dbx:     convertToPbDatabase(tpmfirmwarestate.GetSecureBoot().GetDbx()),
			Pk:      convertToPbDatabase(tpmfirmwarestate.GetSecureBoot().GetPk()),
			Kek:     convertToPbDatabase(tpmfirmwarestate.GetSecureBoot().GetKek()),
		}
	}

	var efiState *pb.EfiState
	if tpmfirmwarestate.GetEfi() != nil {
		efiState = &pb.EfiState{}
		efiState.Apps = make([]*pb.EfiApp, len(tpmfirmwarestate.GetEfi().GetApps()))
		efiState.BootServicesDrivers = make([]*pb.EfiApp, len(tpmfirmwarestate.GetEfi().GetBootServicesDrivers()))
		efiState.RuntimeServicesDrivers = make([]*pb.EfiApp, len(tpmfirmwarestate.GetEfi().GetRuntimeServicesDrivers()))

		for i, app := range tpmfirmwarestate.GetEfi().GetApps() {
			efiState.Apps[i] = &pb.EfiApp{Digest: app.GetDigest()}
		}
		for i, app := range tpmfirmwarestate.GetEfi().GetBootServicesDrivers() {
			efiState.BootServicesDrivers[i] = &pb.EfiApp{Digest: app.GetDigest()}
		}
		for i, app := range tpmfirmwarestate.GetEfi().GetRuntimeServicesDrivers() {
			efiState.RuntimeServicesDrivers[i] = &pb.EfiApp{Digest: app.GetDigest()}
		}
	}

	var rawEvents []*pb.Event
	if tpmfirmwarestate.GetRawEvents() != nil {
		rawEvents = make([]*pb.Event, len(tpmfirmwarestate.GetRawEvents()))
		for i, event := range tpmfirmwarestate.GetRawEvents() {
			rawEvents[i] = &pb.Event{
				PcrIndex:       uint32(event.GetPcrIndex()),
				UntrustedType:  uint32(event.GetUntrustedType()),
				Data:           event.GetData(),
				Digest:         event.GetDigest(),
				DigestVerified: event.GetDigestVerified(),
			}
		}
	}

	var grubState *pb.GrubState
	if tpmfirmwarestate.GetGrub() != nil {
		grubState = &pb.GrubState{}
		files := make([]*pb.GrubFile, len(tpmfirmwarestate.GetGrub().GetFiles()))
		for i, file := range tpmfirmwarestate.GetGrub().GetFiles() {
			files[i] = &pb.GrubFile{
				Digest:            file.GetDigest(),
				UntrustedFilename: file.GetUntrustedFilename(),
			}
		}
		grubState.Files = files
		grubState.Commands = tpmfirmwarestate.GetGrub().GetCommands()
	}

	var linuxKernel *pb.LinuxKernelState
	if tpmfirmwarestate.GetLinuxKernel() != nil {
		linuxKernel = &pb.LinuxKernelState{CommandLine: tpmfirmwarestate.GetLinuxKernel().GetCommandLine()}
	}

	return &pb.MachineState{
		Platform:    platformstate,
		SecureBoot:  secureBootState,
		Efi:         efiState,
		RawEvents:   rawEvents,
		Hash:        tpmpb.HashAlgo(tpmfirmwarestate.GetHash()),
		Grub:        grubState,
		LinuxKernel: linuxKernel,
	}, nil
}

// ConvertToFirmwareState converts a MachineState to a go-eventlog FirmwareLogState
// This is essentially an inverse function for ConvertToMachineState
func ConvertToFirmwareState(ms *pb.MachineState) (*gepb.FirmwareLogState, error) {
	if ms == nil {
		return nil, nil
	}

	var platformState *gepb.PlatformState
	if ms.GetPlatform() != nil {
		platformState = &gepb.PlatformState{}
		switch ms.GetPlatform().GetTechnology() {
		case pb.GCEConfidentialTechnology_AMD_SEV:
			platformState.Technology = gepb.GCEConfidentialTechnology_AMD_SEV
		case pb.GCEConfidentialTechnology_AMD_SEV_ES:
			platformState.Technology = gepb.GCEConfidentialTechnology_AMD_SEV_ES
		case pb.GCEConfidentialTechnology_INTEL_TDX:
			platformState.Technology = gepb.GCEConfidentialTechnology_INTEL_TDX
		case pb.GCEConfidentialTechnology_AMD_SEV_SNP:
			platformState.Technology = gepb.GCEConfidentialTechnology_AMD_SEV_SNP
		case pb.GCEConfidentialTechnology_NONE:
			platformState.Technology = gepb.GCEConfidentialTechnology_NONE
		default:
			return nil, fmt.Errorf("unsupported GCE confidential technology: %v", ms.GetPlatform().GetTechnology())
		}
		switch fw := ms.GetPlatform().GetFirmware().(type) {
		case *pb.PlatformState_GceVersion:
			platformState.Firmware = &gepb.PlatformState_GceVersion{GceVersion: fw.GceVersion}
		case *pb.PlatformState_ScrtmVersionId:
			platformState.Firmware = &gepb.PlatformState_ScrtmVersionId{ScrtmVersionId: fw.ScrtmVersionId}
		}
	}

	var secureBootState *gepb.SecureBootState
	if ms.GetSecureBoot() != nil {
		secureBootState = &gepb.SecureBootState{
			Enabled: ms.GetSecureBoot().GetEnabled(),
			Db:      convertFromPbDatabase(ms.GetSecureBoot().GetDb()),
			Dbx:     convertFromPbDatabase(ms.GetSecureBoot().GetDbx()),
			Pk:      convertFromPbDatabase(ms.GetSecureBoot().GetPk()),
			Kek:     convertFromPbDatabase(ms.GetSecureBoot().GetKek()),
		}
	}

	var efiState *gepb.EfiState
	if ms.GetEfi() != nil {
		efiState = &gepb.EfiState{}
		efiState.Apps = make([]*gepb.EfiApp, len(ms.GetEfi().GetApps()))
		efiState.BootServicesDrivers = make([]*gepb.EfiApp, len(ms.GetEfi().GetBootServicesDrivers()))
		efiState.RuntimeServicesDrivers = make([]*gepb.EfiApp, len(ms.GetEfi().GetRuntimeServicesDrivers()))

		for i, app := range ms.GetEfi().GetApps() {
			efiState.Apps[i] = &gepb.EfiApp{Digest: app.GetDigest()}
		}
		for i, app := range ms.GetEfi().GetBootServicesDrivers() {
			efiState.BootServicesDrivers[i] = &gepb.EfiApp{Digest: app.GetDigest()}
		}
		for i, app := range ms.GetEfi().GetRuntimeServicesDrivers() {
			efiState.RuntimeServicesDrivers[i] = &gepb.EfiApp{Digest: app.GetDigest()}
		}
	}

	var rawEvents []*gepb.Event
	if ms.GetRawEvents() != nil {
		rawEvents = make([]*gepb.Event, len(ms.GetRawEvents()))
		for i, event := range ms.GetRawEvents() {
			rawEvents[i] = &gepb.Event{
				PcrIndex: uint32(event.GetPcrIndex()),
				// UntrustedType is not present in pb.Event, so it will be 0
				Data:           event.GetData(),
				Digest:         event.GetDigest(),
				DigestVerified: event.GetDigestVerified(),
			}
		}
	}

	var grubState *gepb.GrubState
	if ms.GetGrub() != nil {
		grubState = &gepb.GrubState{}
		files := make([]*gepb.GrubFile, len(ms.GetGrub().GetFiles()))
		for i, file := range ms.GetGrub().GetFiles() {
			files[i] = &gepb.GrubFile{
				Digest: file.GetDigest(),
				// UntrustedFilename is not present in pb.GrubFile, so it will be nil
			}
		}
		grubState.Files = files
		grubState.Commands = ms.GetGrub().GetCommands()
	}

	var linuxKernel *gepb.LinuxKernelState
	if ms.GetLinuxKernel() != nil {
		linuxKernel = &gepb.LinuxKernelState{CommandLine: ms.GetLinuxKernel().GetCommandLine()}
	}

	return &gepb.FirmwareLogState{
		Platform:    platformState,
		SecureBoot:  secureBootState,
		Efi:         efiState,
		RawEvents:   rawEvents,
		Hash:        gepb.HashAlgo(ms.GetHash()),
		Grub:        grubState,
		LinuxKernel: linuxKernel,
	}, nil
}

// convertFromPbDatabase converts a MachineState.Database to a go-eventlog.Database.
func convertFromPbDatabase(pbdb *pb.Database) *gepb.Database {
	if pbdb == nil {
		return nil
	}
	gepbCerts := make([]*gepb.Certificate, 0, len(pbdb.GetCerts()))
	for _, c := range pbdb.GetCerts() {
		var gepbCert gepb.Certificate
		switch rep := c.GetRepresentation().(type) {
		case *pb.Certificate_Der:
			gepbCert.Representation = &gepb.Certificate_Der{Der: rep.Der}
		case *pb.Certificate_WellKnown:
			if wkEnum, ok := gepb.WellKnownCertificate_value[rep.WellKnown.String()]; ok {
				gepbCert.Representation = &gepb.Certificate_WellKnown{WellKnown: gepb.WellKnownCertificate(wkEnum)}
			} else {
				// If the well-known enum doesn't map directly, treat it as unknown
				gepbCert.Representation = &gepb.Certificate_WellKnown{WellKnown: gepb.WellKnownCertificate_UNKNOWN}
			}
		}
		gepbCerts = append(gepbCerts, &gepbCert)
	}
	return &gepb.Database{
		Certs:  gepbCerts,
		Hashes: pbdb.GetHashes(),
	}

}

// ParseCosCELPCR takes an encoded COS CEL and PCR bank, replays the CEL against the PCRs,
// and returns the AttestedCosState
func ParseCosCELPCR(cosEventLog []byte, p register.PCRBank) (*pb.AttestedCosState, error) {
	return getCosStateFromCEL(cosEventLog, p, gecel.PCRType)
}

// ParseCosCELRTMR takes in a raw COS CEL and a RTMR bank, validates and returns it's
// COS states as parts of the MachineState.
func ParseCosCELRTMR(cosEventLog []byte, r register.RTMRBank) (*pb.AttestedCosState, error) {
	return getCosStateFromCEL(cosEventLog, r, gecel.CCMRType)
}

func getCosStateFromCEL(rawCanonicalEventLog []byte, register register.MRBank, trustingRegisterType gecel.MRType) (*pb.AttestedCosState, error) {
	decodedCEL, err := gecel.DecodeToCEL(bytes.NewBuffer(rawCanonicalEventLog))
	if err != nil {
		return nil, err
	}
	// Validate the COS event log first.
	if err := decodedCEL.Replay(register); err != nil {
		return nil, err
	}

	cosState, err := getVerifiedCosState(decodedCEL, trustingRegisterType)
	if err != nil {
		return nil, err
	}

	return cosState, err
}

// getVerifiedCosState takes in CEL and a register type (can be PCR or CCELMR), and returns the state
// in the CEL. It will only include events using the correct registerType.
func getVerifiedCosState(coscel gecel.CEL, registerType gecel.MRType) (*pb.AttestedCosState, error) {
	cosState := &pb.AttestedCosState{}
	cosState.Container = &pb.ContainerState{}
	cosState.HealthMonitoring = &pb.HealthMonitoringState{}
	cosState.GpuDeviceState = &pb.GpuDeviceState{}
	cosState.Container.Args = make([]string, 0)
	cosState.Container.EnvVars = make(map[string]string)
	cosState.Container.OverriddenEnvVars = make(map[string]string)

	seenSeparator := false
	for _, record := range coscel.Records() {
		if record.IndexType != registerType {
			return nil, fmt.Errorf("expect registerType: %d, but get %d in a CEL record", registerType, record.IndexType)
		}

		switch record.IndexType {
		case gecel.PCRType:
			if record.Index != cel.CosEventPCR {
				return nil, fmt.Errorf("found unexpected PCR %d in COS CEL log", record.Index)
			}
		case gecel.CCMRType:
			if record.Index != cel.CosCCELMRIndex {
				return nil, fmt.Errorf("found unexpected CCELMR %d in COS CEL log", record.Index)
			}
		default:
			return nil, fmt.Errorf("unknown COS CEL log index type %d", record.IndexType)
		}

		// The Content.Type is not verified at this point, so we have to fail
		// if we see any events that we do not understand. This ensures that
		// we either verify the digest of event event in this PCR, or we fail
		// to replay the event log.
		// TODO: See if we can fix this to have the Content Type be verified.
		cosTlv, err := cel.ParseToCosTlv(record.Content)
		if err != nil {
			return nil, err
		}

		// verify digests for the cos cel content
		if err := gecel.VerifyDigests(cosTlv, record.Digests); err != nil {
			return nil, err
		}

		// TODO: Add support for post-separator container data
		if seenSeparator {
			return nil, fmt.Errorf("found COS Event Type %v after LaunchSeparator event", cosTlv.EventType)
		}

		switch cosTlv.EventType {
		case cel.ImageRefType:
			if cosState.Container.GetImageReference() != "" {
				return nil, fmt.Errorf("found more than one ImageRef event")
			}
			cosState.Container.ImageReference = string(cosTlv.EventContent)

		case cel.ImageDigestType:
			if cosState.Container.GetImageDigest() != "" {
				return nil, fmt.Errorf("found more than one ImageDigest event")
			}
			cosState.Container.ImageDigest = string(cosTlv.EventContent)

		case cel.RestartPolicyType:
			restartPolicy, ok := pb.RestartPolicy_value[string(cosTlv.EventContent)]
			if !ok {
				return nil, fmt.Errorf("unknown restart policy in COS eventlog: %s", string(cosTlv.EventContent))
			}
			cosState.Container.RestartPolicy = pb.RestartPolicy(restartPolicy)

		case cel.ImageIDType:
			if cosState.Container.GetImageId() != "" {
				return nil, fmt.Errorf("found more than one ImageId event")
			}
			cosState.Container.ImageId = string(cosTlv.EventContent)

		case cel.EnvVarType:
			envName, envVal, err := cel.ParseEnvVar(string(cosTlv.EventContent))
			if err != nil {
				return nil, err
			}
			cosState.Container.EnvVars[envName] = envVal

		case cel.ArgType:
			cosState.Container.Args = append(cosState.Container.Args, string(cosTlv.EventContent))

		case cel.OverrideArgType:
			cosState.Container.OverriddenArgs = append(cosState.Container.OverriddenArgs, string(cosTlv.EventContent))

		case cel.OverrideEnvType:
			envName, envVal, err := cel.ParseEnvVar(string(cosTlv.EventContent))
			if err != nil {
				return nil, err
			}
			cosState.Container.OverriddenEnvVars[envName] = envVal
		case cel.LaunchSeparatorType:
			seenSeparator = true
		case cel.MemoryMonitorType:
			enabled := false
			if len(cosTlv.EventContent) == 1 && cosTlv.EventContent[0] == uint8(1) {
				enabled = true
			}
			cosState.HealthMonitoring.MemoryEnabled = &enabled
		case cel.GpuCCModeType:
			ccMode, ok := pb.GPUDeviceCCMode_value[string(cosTlv.EventContent)]
			if !ok {
				return nil, fmt.Errorf("unknown GPU device CC mode in COS eventlog: %s", string(cosTlv.EventContent))
			}
			cosState.GpuDeviceState.CcMode = pb.GPUDeviceCCMode(ccMode)

		// TODO: add support for GPU Device Attestation Binding Event
		// case cel.GPUDeviceAttestationBindingType:

		default:
			return nil, fmt.Errorf("found unknown COS Event Type %v", cosTlv.EventType)
		}

	}
	return cosState, nil
}

func convertToPbDatabase(gedb *gepb.Database) *pb.Database {
	if gedb == nil {
		return nil
	}
	protoCerts := make([]*pb.Certificate, 0, len(gedb.GetCerts()))
	for _, c := range gedb.GetCerts() {
		var pbCert pb.Certificate
		if wkEnum, err := matchWellKnownCert(c); err != nil {
			pbCert.Representation = &pb.Certificate_Der{Der: c.GetDer()}
		} else {
			pbCert.Representation = &pb.Certificate_WellKnown{WellKnown: wkEnum}

		}
		protoCerts = append(protoCerts, &pbCert)
	}
	return &pb.Database{
		Certs:  protoCerts,
		Hashes: gedb.GetHashes(),
	}
}

func matchWellKnownCert(cert *gepb.Certificate) (pb.WellKnownCertificate, error) {
	if cert.GetWellKnown() == gepb.WellKnownCertificate_UNKNOWN {
		return pb.WellKnownCertificate_UNKNOWN, errors.New("failed to match well known certificate")
	}
	if wkEnum, ok := pb.WellKnownCertificate_value[cert.GetWellKnown().String()]; ok {
		return pb.WellKnownCertificate(wkEnum), nil
	}
	return pb.WellKnownCertificate_UNKNOWN, errors.New("failed to match well known certificate")
}
