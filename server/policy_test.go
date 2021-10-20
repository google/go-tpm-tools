package server

import (
	"testing"

	"github.com/google/go-tpm-tools/proto/attest"
	pb "github.com/google/go-tpm-tools/proto/attest"
)

var (
	defaultGcePolicy = pb.Policy{
		Platform: &pb.PlatformPolicy{
			MinimumGceFirmwareVersion: 1,
			MinimumTechnology:         pb.GCEConfidentialTechnology_NONE,
		},
	}
	defaultPhysicalPolicy = pb.Policy{
		Platform: &pb.PlatformPolicy{
			AllowedScrtmVersionIds: [][]byte{},
		},
	}
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

func TestEvaluatePolicy(t *testing.T) {
	tests := []struct {
		name   string
		log    eventLog
		policy *pb.Policy
	}{
		{"Debian10-SHA1", Debian10GCE, &defaultGcePolicy},
		{"RHEL8-CryptoAgile", Rhel8GCE, &defaultGcePolicy},
		{"Ubuntu1804AmdSev-CryptoAgile", UbuntuAmdSevGCE, &defaultGcePolicy},
		{"Ubuntu2104NoDbx-CryptoAgile", Ubuntu2104NoDbxGCE, &defaultGcePolicy},
		{"Ubuntu2104NoSecureBoot-CryptoAgile", Ubuntu2104NoSecureBootGCE, &defaultGcePolicy},
		{"GlinuxNoSecureBoot-CryptoAgile", GlinuxNoSecureBootLaptop, &defaultPhysicalPolicy},
		{"ArchLinuxWorkstation-CryptoAgile", ArchLinuxWorkstation, &defaultPhysicalPolicy},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			machineState, err := ParseMachineState(test.log.RawLog, test.log.Banks[0])
			if err != nil {
				t.Fatalf("failed to get machine state: %v", err)
			}
			if err := EvaluatePolicy(machineState, test.policy); err != nil {
				t.Errorf("failed to apply policy: %v", err)
			}
		})
	}
}

func TestEvaluatePolicySCRTM(t *testing.T) {
	archLinuxWorkstationSCRTMPolicy := pb.Policy{
		Platform: &pb.PlatformPolicy{
			AllowedScrtmVersionIds: [][]byte{{0x1e, 0xfb, 0x6b, 0x54, 0x0c, 0x1d, 0x55, 0x40, 0xa4, 0xad,
				0x4e, 0xf4, 0xbf, 0x17, 0xb8, 0x3a}},
		},
	}
	machineState, err := ParseMachineState(ArchLinuxWorkstation.RawLog, ArchLinuxWorkstation.Banks[0])
	if err != nil {
		t.Fatalf("failed to get machine state: %v", err)
	}
	if err := EvaluatePolicy(machineState, &archLinuxWorkstationSCRTMPolicy); err != nil {
		t.Errorf("failed to apply policy: %v", err)
	}
}

func TestEvaluatePolicyFailure(t *testing.T) {
	badGcePolicyVersion := pb.Policy{
		Platform: &pb.PlatformPolicy{
			MinimumGceFirmwareVersion: 2,
			MinimumTechnology:         pb.GCEConfidentialTechnology_NONE,
		},
	}
	badGcePolicySEV_ES := pb.Policy{
		Platform: &pb.PlatformPolicy{
			MinimumGceFirmwareVersion: 0,
			MinimumTechnology:         pb.GCEConfidentialTechnology_AMD_SEV_ES,
		},
	}
	badGcePolicySEV := pb.Policy{
		Platform: &pb.PlatformPolicy{
			MinimumGceFirmwareVersion: 0,
			MinimumTechnology:         pb.GCEConfidentialTechnology_AMD_SEV_ES,
		},
	}
	badPhysicalPolicy := pb.Policy{
		Platform: &pb.PlatformPolicy{
			AllowedScrtmVersionIds: [][]byte{{0x00}},
		},
	}
	tests := []struct {
		name   string
		log    eventLog
		policy *pb.Policy
	}{
		{"Debian10-SHA1", Debian10GCE, &badGcePolicyVersion},
		{"Debian10-SHA1", Debian10GCE, &badGcePolicySEV},
		{"Ubuntu1804AmdSev-CryptoAgile", UbuntuAmdSevGCE, &badGcePolicySEV_ES},
		{"GlinuxNoSecureBoot-CryptoAgile", GlinuxNoSecureBootLaptop, &badPhysicalPolicy},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			machineState, err := ParseMachineState(test.log.RawLog, test.log.Banks[0])
			if err != nil {
				t.Fatalf("failed to get machine state: %v", err)
			}
			if err := EvaluatePolicy(machineState, test.policy); err == nil {
				t.Errorf("expected policy failure; got success")
			}
		})
	}
}
