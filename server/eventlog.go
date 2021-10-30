package server

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"

	"github.com/google/go-attestation/attest"
	pb "github.com/google/go-tpm-tools/proto/attest"
	tpmpb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/tpm2"
)

// ParseMachineState parses a raw event log and replays the parsed event
// log against the given PCR values. It returns the corresponding MachineState
// containing the events verified by particular PCR indexes/digests. An error is
// returned if the replay for any PCR index does not match the provided value.
//
// It is the caller's responsibility to ensure that the passed PCR values can be
// trusted. Users can establish trust in PCR values by either calling
// client.ReadPCRs() themselves or by verifying the values via a PCR quote.
func ParseMachineState(rawEventLog []byte, pcrs *tpmpb.PCRs) (*pb.MachineState, error) {
	events, err := parseReplayHelper(rawEventLog, pcrs)
	if err != nil {
		return nil, err
	}
	// error is already checked in convertToAttestPcrs
	cryptoHash, _ := tpm2.Algorithm(pcrs.GetHash()).Hash()

	rawEvents := convertToPbEvents(cryptoHash, events)
	platform, err := getPlatformState(cryptoHash, rawEvents)
	if err != nil {
		// Eventually, we want to support a partial failure model.
		// The MachineState can contain empty {Platform,SecureBoot}States when
		// those individually fail parsing. The error will contain suberrors
		// for the fields in MachineState that failed parsing.
		//
		// For now, since the MachineState only comprises PlatformState, we
		// return an empty MachineState with empty platform state and the error.
		return &pb.MachineState{}, err
	}

	return &pb.MachineState{
		Platform:  platform,
		RawEvents: rawEvents,
		Hash:      pcrs.GetHash(),
	}, nil
}

func contains(set [][]byte, value []byte) bool {
	for _, setItem := range set {
		if bytes.Equal(value, setItem) {
			return true
		}
	}
	return false
}

func getPlatformState(hash crypto.Hash, events []*pb.Event) (*pb.PlatformState, error) {
	// We pre-compute the separator event hash, and check if the event type has
	// been modified. We only trust events that come before a valid separator.
	hasher := hash.New()
	// From the PC Client Firmware Profile spec, on the separator event:
	// The event field MUST contain the hex value 00000000h or FFFFFFFFh.
	separatorData := [][]byte{{0, 0, 0, 0}, {0xff, 0xff, 0xff, 0xff}}
	separatorDigests := make([][]byte, 0, len(separatorData))
	for _, value := range separatorData {
		hasher.Write(value)
		separatorDigests = append(separatorDigests, hasher.Sum(nil))
	}

	var versionString []byte
	var nonHostInfo []byte
	for _, event := range events {
		index := event.GetPcrIndex()
		if index != 0 {
			continue
		}
		evtType := event.GetUntrustedType()

		// Make sure we have a valid separator event, we check any event that
		// claims to be a Separator or "looks like" a separator to prevent
		// certain vulnerabilities in event parsing. For more info see:
		// https://github.com/google/go-attestation/blob/master/docs/event-log-disclosure.md
		if (evtType == Separator) || contains(separatorDigests, event.GetDigest()) {
			if evtType != Separator {
				return nil, fmt.Errorf("PCR%d event contains separator data but non-separator type %d", index, evtType)
			}
			if !event.GetDigestVerified() {
				return nil, fmt.Errorf("unverified separator digest for PCR%d", index)
			}
			if !contains(separatorData, event.GetData()) {
				return nil, fmt.Errorf("invalid separator data for PCR%d", index)
			}
			// Don't trust any PCR0 events after the separator
			break
		}

		if evtType == SCRTMVersion {
			if !event.GetDigestVerified() {
				return nil, fmt.Errorf("invalid SCRTM version event for PCR%d", index)
			}
			versionString = event.GetData()
		}

		if evtType == NonhostInfo {
			if !event.GetDigestVerified() {
				return nil, fmt.Errorf("invalid Non-Host info event for PCR%d", index)
			}
			nonHostInfo = event.GetData()
		}
	}

	state := &pb.PlatformState{}
	if gceVersion, err := ConvertSCRTMVersionToGCEFirmwareVersion(versionString); err == nil {
		state.Firmware = &pb.PlatformState_GceVersion{GceVersion: gceVersion}
	} else {
		state.Firmware = &pb.PlatformState_ScrtmVersionId{ScrtmVersionId: versionString}
	}

	if tech, err := ParseGCENonHostInfo(nonHostInfo); err == nil {
		state.Technology = tech
	}

	return state, nil
}

// Separate helper function so we can use attest.ParseSecurebootState without
// needing to reparse the entire event log.
func parseReplayHelper(rawEventLog []byte, pcrs *tpmpb.PCRs) ([]attest.Event, error) {
	attestPcrs, err := convertToAttestPcrs(pcrs)
	if err != nil {
		return nil, fmt.Errorf("received bad PCR proto: %v", err)
	}
	eventLog, err := attest.ParseEventLog(rawEventLog)
	if err != nil {
		return nil, fmt.Errorf("failed to parse event log: %v", err)
	}
	events, err := eventLog.Verify(attestPcrs)
	if err != nil {
		return nil, fmt.Errorf("failed to replay event log: %v", err)
	}
	return events, nil
}

func convertToAttestPcrs(pcrProto *tpmpb.PCRs) ([]attest.PCR, error) {
	if len(pcrProto.GetPcrs()) == 0 {
		return nil, errors.New("no PCRs to convert")
	}
	hash := tpm2.Algorithm(pcrProto.GetHash())
	cryptoHash, err := hash.Hash()
	if err != nil {
		return nil, err
	}

	attestPcrs := make([]attest.PCR, 0, len(pcrProto.GetPcrs()))
	for index, digest := range pcrProto.GetPcrs() {
		attestPcrs = append(attestPcrs, attest.PCR{
			Index:     int(index),
			Digest:    digest,
			DigestAlg: cryptoHash,
		})
	}
	return attestPcrs, nil
}

func convertToPbEvents(hash crypto.Hash, events []attest.Event) []*pb.Event {
	pbEvents := make([]*pb.Event, len(events))
	for i, event := range events {
		hasher := hash.New()
		hasher.Write(event.Data)
		digest := hasher.Sum(nil)

		pbEvents[i] = &pb.Event{
			PcrIndex:       uint32(event.Index),
			UntrustedType:  uint32(event.Type),
			Data:           event.Data,
			Digest:         event.Digest,
			DigestVerified: bytes.Equal(digest, event.Digest),
		}
	}
	return pbEvents
}
