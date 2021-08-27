package server

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/google/go-attestation/attest"
	pb "github.com/google/go-tpm-tools/proto/attest"
	tpmpb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/tpm2"
)

// ParseAndReplayEventLog parses a raw event log and replays the parsed event
// log against the given PCR values. It returns the corresponding MachineState
// containing the events verified by particular PCR indexes/digests. An error is
// returned if the replay for any PCR index does not match the provided value.
//
// It is the caller's responsibility to ensure that the passed PCR values can be
// trusted. Users can establish trust in PCR values by either calling
// client.ReadPCRs() themselves or by verifying the values via a PCR quote.
func ParseAndReplayEventLog(rawEventLog []byte, pcrs *tpmpb.PCRs) (*pb.MachineState, error) {
	events, err := parseReplayHelper(rawEventLog, pcrs)
	if err != nil {
		return nil, err
	}

	rawEvents := convertToPbEvents(pcrs.GetHash(), events)
	platform, err := getPlatfromState(rawEvents)
	if err != nil {
		return nil, err
	}

	return &pb.MachineState{
		Platform:  platform,
		RawEvents: rawEvents,
		Hash:      pcrs.GetHash(),
	}, nil
}

func getPlatfromState(events []*pb.Event) (*pb.PlatformState, error) {
	return &pb.PlatformState{}, nil
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

func convertToPbEvents(alg tpmpb.HashAlgo, events []attest.Event) []*pb.Event {
	// error is already checked in convertToAttestPcrs
	hash, _ := tpm2.Algorithm(alg).Hash()

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
