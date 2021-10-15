package server

import (
	"testing"

	"github.com/google/go-tpm-tools/proto/attest"
)

func TestNilPolicyAlwaysPasses(t *testing.T) {
	subtests := []struct {
		name  string
		state *attest.MachineState
	}{
		{"NilState", nil},
		{"PlatformState", &attest.MachineState{
			Platform: &attest.PlatformState{
				Firmware:   &attest.PlatformState_GceVersion{GceVersion: 1},
				Technology: attest.GCEConfidentialTechnology_AMD_SEV,
			},
		}},
	}
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			if err := EvaluatePolicy(subtest.state, nil); err != nil {
				t.Errorf("nil policy should always succeed: %v", err)
			}
		})
	}
}

func TestGCEFirmwareVersionSimple(t *testing.T) {
	zero := ConvertGCEFirmwareVersionToSCRTMVersion(0)
	if len(zero) != 0 {
		t.Errorf("expected empty SCRTM version, got %x", zero)
	}
	ver, err := ConvertSCRTMVersionToGCEFirmwareVersion(
		ConvertGCEFirmwareVersionToSCRTMVersion(23),
	)
	if ver != 23 {
		t.Errorf("convert functions aren't inverses, got %d: %v", ver, err)
	}
}
