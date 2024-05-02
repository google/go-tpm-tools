package server

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	gcesev "github.com/google/gce-tcb-verifier/sev"
	gceverify "github.com/google/gce-tcb-verifier/verify"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	svalidate "github.com/google/go-sev-guest/validate"
	"github.com/google/go-sev-guest/verify/trust"
	pb "github.com/google/go-tpm-tools/proto/attest"
)

// EvaluatePolicy succeeds if the provided MachineState complies with the
// provided policy. If the state does not pass the policy, the returned error
// will describe in what way the state failed. See the Policy documentation for
// more information about the specifics of different policies.
func EvaluatePolicy(state *pb.MachineState, policy *pb.Policy) error {
	return EvaluatePolicyOpt(state, policy, DefaultPolicyOptions())
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

// EvaluatePolicyOpt succeeds if the provided MachineState complies
// with the provided policy subject to given policy options. If the
// state does not pass the policy, the returned error will describe in
// what way the state failed. See the Policy documentation for more
// information about the specifics of different policies.
func EvaluatePolicyOpt(state *pb.MachineState, policy *pb.Policy, opts *PolicyOptions) error {
	if err := evaluatePlatformPolicy(state.GetPlatform(), policy.GetPlatform()); err != nil {
		return err
	}
	if state.GetTeeAttestation() == nil {
		return nil
	}
	switch at := state.TeeAttestation.(type) {
	case *pb.MachineState_SevSnpAttestation:
		return evaluateSevSnpPolicy(at.SevSnpAttestation, policy.GetSevSnp(), opts)
	case *pb.MachineState_TdxAttestation:
		// Currently unchecked.
		return nil
	default:
		return fmt.Errorf("no policy for TEE attestation type %T", state.TeeAttestation)
	}
}

func rootOfTrust(certs [][]byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for _, der := range certs {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		pool.AddCert(cert)
	}
	return pool, nil
}

// the SEV-SNP attestation signature is already verified by this point.
func evaluateSevSnpPolicy(state *spb.Attestation, policy *pb.SevSnpPolicy, opts *PolicyOptions) error {
	if state == nil {
		return fmt.Errorf("attestation is nil")
	}
	// No UEFI policy. Done.
	if policy.GetUefi() == nil {
		return nil
	}
	// Extract which certs to trust as root for keys that sign uefi measurements
	uefirot, err := rootOfTrust(policy.GetUefi().GetRootCerts())
	if err != nil {
		return err
	}
	kind := svalidate.CertEntryKind(svalidate.CertEntryAllowMissing)
	if policy.GetUefi().GetRequireSigned() {
		kind = svalidate.CertEntryRequire
	}
	if opts == nil {
		opts = DefaultPolicyOptions()
	}
	// Check a SEV-SNP attestation's extra certificate table for signed uefi measurements
	// and apply the verification logic against the attestation measurement.
	vopts := &svalidate.Options{
		GuestPolicy: defaultSevSnpGuestPolicy,
		CertTableOptions: map[string]*svalidate.CertEntryOption{
			gcesev.GCEFwCertGUID: {
				Kind: kind,
				Validate: gceverify.SNPValidateFunc(&gceverify.Options{
					SNP:          &gceverify.SNPOptions{},
					RootsOfTrust: uefirot,
					Now:          opts.Now,
					Getter:       opts.Getter,
				})}}}
	return svalidate.SnpAttestation(state, vopts)
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
