package server

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/google/go-sev-guest/verify/trust"
	pb "github.com/google/go-tpm-tools/proto/attest"
)

// EvaluatePolicy succeeds if the provided MachineState complies with the
// provided policy. If the state does not pass the policy, the returned error
// will describe in what way the state failed. See the Policy documentation for
// more information about the specifics of different policies.
func EvaluatePolicy(state *pb.MachineState, policy *pb.Policy) error {
	if err := evaluatePlatformPolicy(state.GetPlatform(), policy.GetPlatform()); err != nil {
		return err
	}
	return nil
}

// PolicyOptions provides extra options for evaluating policy.
type PolicyOptions struct {
	// Getter allows the policy evaluator to download reference materials if needed.
	Getter trust.HTTPSGetter
	// Now is the time to evaluate time-based constraints against.
	Now time.Time
}

// DefaultPolicyOptions returns a useful default for PolicyOptions.
func DefaultPolicyOptions() *PolicyOptions {
	return &PolicyOptions{
		Getter: trust.DefaultHTTPSGetter(),
		Now:    time.Now(),
	}
}

func evaluatePlatformPolicy(state *pb.PlatformState, policy *pb.PlatformPolicy) error {
	allowedVersions := policy.GetAllowedScrtmVersionIds()
	if len(allowedVersions) > 0 {
		if err := hasAllowedVersion(state, allowedVersions); err != nil {
			return err
		}
	}

	minGceVersion := policy.GetMinimumGceFirmwareVersion()
	gceVersion := state.GetGceVersion()
	if minGceVersion > gceVersion {
		return fmt.Errorf("expected GCE Version %d or later, got %d", minGceVersion, gceVersion)
	}
	minTech := policy.GetMinimumTechnology()
	tech := state.GetTechnology()
	if minTech > tech {
		return fmt.Errorf("expected a GCE Confidential Technology of %d or later, got %d", minTech, tech)
	}
	return nil
}

func hasAllowedVersion(state *pb.PlatformState, allowedVersions [][]byte) error {
	firmware := state.GetFirmware()

	// We want the version check to work even for a GCE VM.
	var version []byte
	if scrtm, ok := firmware.(*pb.PlatformState_ScrtmVersionId); ok {
		version = scrtm.ScrtmVersionId
	} else if gce, ok := firmware.(*pb.PlatformState_GceVersion); ok {
		version = ConvertGCEFirmwareVersionToSCRTMVersion(gce.GceVersion)
	} else {
		return errors.New("missing SCRTM version in PlatformState")
	}
	for _, allowed := range allowedVersions {
		if bytes.Equal(version, allowed) {
			return nil
		}
	}
	return fmt.Errorf("provided SCRTM version (%x) not allowed", version)
}
