package server

import (
	"bytes"
	"errors"
	"fmt"

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
		return nil, fmt.Errorf("unsupported bootloader option for event log extraction: %v", opts.Loader)
	}

	tcghashalgo := gepb.HashAlgo(pcrs.GetHash())
	cryptoHashAlg, err := tcghashalgo.CryptoHash()
	if err != nil {
		return nil, err
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
		return nil, fmt.Errorf("failed to replay and extract TPM PCClient event log: %w", err)
	}

	return convertToMachineState(tpmfirmwarestate)
}

func convertToMachineState(tpmfirmwarestate *gepb.FirmwareLogState) (*pb.MachineState, error) {
	var platformstate *pb.PlatformState
	if tpmfirmwarestate.GetPlatform() != nil {
		platformstate = &pb.PlatformState{
			Technology: func() pb.GCEConfidentialTechnology {
				switch tpmfirmwarestate.GetPlatform().GetTechnology() {
				case gepb.GCEConfidentialTechnology_AMD_SEV:
					return pb.GCEConfidentialTechnology_AMD_SEV
				case gepb.GCEConfidentialTechnology_AMD_SEV_ES:
					return pb.GCEConfidentialTechnology_AMD_SEV_ES
				case gepb.GCEConfidentialTechnology_INTEL_TDX:
					return pb.GCEConfidentialTechnology_INTEL_TDX
				case gepb.GCEConfidentialTechnology_AMD_SEV_SNP:
					return pb.GCEConfidentialTechnology_AMD_SEV_SNP
				default:
					return pb.GCEConfidentialTechnology_NONE
				}
			}(),
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
		apps := make([]*pb.EfiApp, len(tpmfirmwarestate.GetEfi().GetApps()))
		for i, app := range tpmfirmwarestate.GetEfi().GetApps() {
			apps[i] = &pb.EfiApp{Digest: app.GetDigest()}
		}
		efiState.Apps = apps
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
		Hash:        tpmpb.HashAlgo(tpmfirmwarestate.Hash),
		Grub:        grubState,
		LinuxKernel: linuxKernel,
	}, nil
}

// ParseCosCELPCR takes an encoded COS CEL and PCR bank, replays the CEL against the PCRs,
// and returns the AttestedCosState
func ParseCosCELPCR(cosEventLog []byte, p register.PCRBank) (*pb.AttestedCosState, error) {
	return getCosStateFromCEL(cosEventLog, p, cel.PCRTypeValue)
}

// ParseCosCELRTMR takes in a raw COS CEL and a RTMR bank, validates and returns it's
// COS states as parts of the MachineState.
func ParseCosCELRTMR(cosEventLog []byte, r register.RTMRBank) (*pb.AttestedCosState, error) {
	return getCosStateFromCEL(cosEventLog, r, cel.CCMRTypeValue)
}

func getCosStateFromCEL(rawCanonicalEventLog []byte, register register.MRBank, trustingRegisterType uint8) (*pb.AttestedCosState, error) {
	decodedCEL, err := cel.DecodeToCEL(bytes.NewBuffer(rawCanonicalEventLog))
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
func getVerifiedCosState(coscel cel.CEL, registerType uint8) (*pb.AttestedCosState, error) {
	cosState := &pb.AttestedCosState{}
	cosState.Container = &pb.ContainerState{}
	cosState.HealthMonitoring = &pb.HealthMonitoringState{}
	cosState.GpuDeviceState = &pb.GpuDeviceState{}
	cosState.Container.Args = make([]string, 0)
	cosState.Container.EnvVars = make(map[string]string)
	cosState.Container.OverriddenEnvVars = make(map[string]string)

	seenSeparator := false
	for _, record := range coscel.Records {
		if record.IndexType != registerType {
			return nil, fmt.Errorf("expect registerType: %d, but get %d in a CEL record", registerType, record.IndexType)
		}

		switch record.IndexType {
		case cel.PCRTypeValue:
			if record.Index != cel.CosEventPCR {
				return nil, fmt.Errorf("found unexpected PCR %d in COS CEL log", record.Index)
			}
		case cel.CCMRTypeValue:
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
		cosTlv, err := record.Content.ParseToCosTlv()
		if err != nil {
			return nil, err
		}

		// verify digests for the cos cel content
		if err := cel.VerifyDigests(cosTlv, record.Digests); err != nil {
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

		default:
			return nil, fmt.Errorf("found unknown COS Event Type %v", cosTlv.EventType)
		}

	}
	return cosState, nil
}

func convertToPbDatabase(cert *gepb.Database) *pb.Database {
	if cert == nil {
		return nil
	}
	protoCerts := make([]*pb.Certificate, 0, len(cert.GetCerts()))
	for _, c := range cert.GetCerts() {
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
		Hashes: cert.GetHashes(),
	}
}

func matchWellKnownCert(cert *gepb.Certificate) (pb.WellKnownCertificate, error) {
	if cert.GetWellKnown() != gepb.WellKnownCertificate_UNKNOWN {
		if wkEnum, ok := pb.WellKnownCertificate_value[cert.GetWellKnown().String()]; ok {
			return pb.WellKnownCertificate(wkEnum), nil
		}
	}
	return pb.WellKnownCertificate_UNKNOWN, errors.New("failed to match well known certificate")
}
