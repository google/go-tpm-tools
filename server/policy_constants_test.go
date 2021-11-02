package server

import (
	"testing"

	pb "github.com/google/go-tpm-tools/proto/attest"
)

func getGceMemoryEncryptionNonhostEvent(memoryEncrypted bool) []byte {
	event := make([]byte, 32)
	copy(event[:], []byte(GCENonHostInfoSignature))
	// event[15] is a null byte.
	if memoryEncrypted {
		event[16] = 0x01
	}
	// Last 15 bytes are reserved.
	return event
}

func TestParseGCENonHostInfo(t *testing.T) {
	nonconfidentialEvent := getGceMemoryEncryptionNonhostEvent( /*memoryEncrypted=*/ false)

	// Empty events should return NONCONFIDENTIAL.
	confTech, err := ParseGCENonHostInfo([]byte{})
	if err == nil {
		t.Error("expected error on incorrect size!")
	}
	if confTech != pb.GCEConfidentialTechnology_NONE {
		t.Errorf("expected ConfidentialTechnology %v, received %v", pb.GCEConfidentialTechnology_NONE, confTech)
	}

	confTech, err = ParseGCENonHostInfo(nonconfidentialEvent)
	if err != nil {
		t.Errorf("failed to parse GCE confidential tech: %v", err)
	}
	if confTech != pb.GCEConfidentialTechnology_NONE {
		t.Errorf("expected ConfidentialTechnology %v, received %v", pb.GCEConfidentialTechnology_NONE, confTech)
	}

	sevEvent := getGceMemoryEncryptionNonhostEvent( /*memoryEncrypted=*/ true)
	confTech, err = ParseGCENonHostInfo(sevEvent)
	if err != nil {
		t.Errorf("failed to parse GCE confidential tech: %v", err)
	}
	if confTech != pb.GCEConfidentialTechnology_AMD_SEV {
		t.Errorf("expected ConfidentialTechnology %v, received %v", pb.GCEConfidentialTechnology_AMD_SEV, confTech)
	}
}

func TestParseGCENonHostInfoUnknownType(t *testing.T) {
	nonconfidentialEvent := getGceMemoryEncryptionNonhostEvent( /*memoryEncrypted=*/ false)
	nonconfidentialEvent[16] = 0x99
	if _, err := ParseGCENonHostInfo(nonconfidentialEvent); err == nil {
		t.Errorf("expected error parsing GCE confidential nonhost event")
	}
}
