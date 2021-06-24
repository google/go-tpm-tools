package server

import (
	"crypto/sha256"
	"testing"

	"github.com/google/go-attestation/attest"
	tpmpb "github.com/google/go-tpm-tools/proto"
)

func TestApplyPolicy(t *testing.T) {
	tests := []struct {
		name           string
		log            eventLog
		extraShimCerts [][]byte
	}{
		{"Debian10-SHA1-EventLog", Debian10GCE, [][]byte{DebianSecureBootCert}},
		{"RHEL8-CryptoAgile-EventLog", Rhel8GCE, [][]byte{RedHatSecureBootCert}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			machineState, err := GetMachineState(test.log.RawLog, test.log.Banks[0])
			if err != nil {
				t.Fatalf("failed to get machine state: %v", err)
			}

			policy, err := DefaultGceLinuxPolicy()
			if err != nil {
				t.Fatalf("failed to create default policy")
			}
			for _, shimCert := range test.extraShimCerts {
				policy.SecureBoot.PermittedAuthorities = append(policy.SecureBoot.PermittedAuthorities,
					&tpmpb.Certificate{Der: shimCert})
			}
			pOut := ApplyAttestationPolicy(policy, machineState)
			pOut.assertNoIssues(t)
		})
	}
}

func TestValidateDefaultGceLinuxPolicy(t *testing.T) {
	policy, err := DefaultGceLinuxPolicy()
	if err != nil {
		t.Fatalf("failed to create default policy")
	}
	if pOut := ValidateAttestationPolicy(policy); len(pOut.Errors) != 0 {
		t.Errorf("failed to validate default policy")
	}
}

func TestValidateEmpty(t *testing.T) {
	badPolicyEmpty := &tpmpb.AttestationPolicy{}

	pOut := ValidateAttestationPolicy(badPolicyEmpty)
	if len(pOut.Errors) != 0 {
		t.Errorf("expected no errors on empty policy")
	}
}

func TestValidateFailed(t *testing.T) {
	badPolicyNotFilled := &tpmpb.AttestationPolicy{
		SecureBoot: &tpmpb.SecureBootPolicy{},
		Platform:   &tpmpb.PlatformPolicy{},
	}
	pOut := ValidateAttestationPolicy(badPolicyNotFilled)
	if len(pOut.Errors) == 0 {
		t.Errorf("expected failure to apply bad policy")
	}
}

func TestApplyPolicyFailedMultipleIssues(t *testing.T) {
	log := Debian10GCE
	sha1Bank := Debian10GCE.Banks[0]

	machineState, err := GetMachineState(log.RawLog, sha1Bank)
	if err != nil {
		t.Fatalf("failed to parse machine state: %v", err)
	}

	// Expect multiple policy errors: db, dbx, and authority
	// (as the default policy is missing shim cert hashes).
	gcePolicy, err := DefaultGceLinuxPolicy()
	if err != nil {
		t.Fatalf("failed to create default policy")
	}
	gcePolicy.SecureBoot.Permitted.Certs = append(gcePolicy.SecureBoot.Permitted.Certs,
		&tpmpb.Certificate{
			Der: RevokedCanonicalBootholeCert,
		})
	machineState.SecureBoot.Dbx.Hashes = nil
	pOut := ApplyAttestationPolicy(gcePolicy, machineState)

	if len(pOut.Errors) <= 1 {
		t.Errorf("expected multiple policy failures")
	}
}

func TestDbSmallerThanSecureBootPolicyDb(t *testing.T) {
	eventLog, err := attest.ParseEventLog(Debian10GCE.RawLog)
	if err != nil {
		t.Fatalf("failed to parse event log: %v", err)
	}
	events := eventLog.Events(attest.HashSHA1)

	attestSbState, err := attest.ParseSecurebootState(events)
	if err != nil {
		t.Fatalf("failed to parse Secure Boot state: %v", err)
	}

	// Add missing authority to policy.
	sbPolicy, err := DefaultGceLinuxSecureBootPolicy()
	if err != nil {
		t.Fatalf("failed to create default linux SB policy: %v", err)
	}
	sbPolicy.PermittedAuthorities = append(sbPolicy.PermittedAuthorities,
		&tpmpb.Certificate{Der: DebianSecureBootCert})

	// Delete a db entry.
	attestSbState.PermittedKeys = attestSbState.PermittedKeys[1:]
	protoSbState, err := convertToProtoSecureBootState(attestSbState)
	if err != nil {
		t.Fatalf("failed to convert SB state to proto: %v", err)
	}

	pOut := applySecureBootPolicy(sbPolicy, protoSbState)
	pOut.assertNoIssues(t)
}

func TestDbxLargerThanSecureBootPolicyDb(t *testing.T) {
	eventLog, err := attest.ParseEventLog(Debian10GCE.RawLog)
	if err != nil {
		t.Fatalf("failed to parse event log: %v", err)
	}
	events := eventLog.Events(attest.HashSHA1)

	attestSbState, err := attest.ParseSecurebootState(events)
	if err != nil {
		t.Fatalf("failed to parse Secure Boot state: %v", err)
	}

	// Add missing authority to policy.
	sbPolicy, err := DefaultGceLinuxSecureBootPolicy()
	if err != nil {
		t.Fatalf("failed to create default linux SB policy: %v", err)
	}
	sbPolicy.PermittedAuthorities = append(sbPolicy.PermittedAuthorities,
		&tpmpb.Certificate{Der: DebianSecureBootCert})

	// Add a dbx entry.
	newEntry := sha256.Sum256([]byte{9, 0, 0, 9})
	attestSbState.ForbiddenHashes = append(attestSbState.ForbiddenHashes, newEntry[:])
	protoSbState, err := convertToProtoSecureBootState(attestSbState)
	if err != nil {
		t.Fatalf("failed to convert SB state to proto: %v", err)
	}

	pOut := applySecureBootPolicy(sbPolicy, protoSbState)
	pOut.assertNoIssues(t)
}

func TestBadDbAgainstValidSecureBootPolicyFails(t *testing.T) {
	eventLog, err := attest.ParseEventLog(Debian10GCE.RawLog)
	if err != nil {
		t.Fatalf("failed to parse event log: %v", err)
	}
	events := eventLog.Events(attest.HashSHA1)

	attestSbState, err := attest.ParseSecurebootState(events)
	if err != nil {
		t.Fatalf("failed to parse Secure Boot state: %v", err)
	}

	// Add a db entry.
	newEntry := sha256.Sum256([]byte{0, 1, 2, 3})
	attestSbState.PermittedHashes = append(attestSbState.PermittedHashes, newEntry[:])
	protoSbState, err := convertToProtoSecureBootState(attestSbState)
	if err != nil {
		t.Fatalf("failed to convert SB state to proto: %v", err)
	}

	sbPolicy, err := DefaultGceLinuxSecureBootPolicy()
	if err != nil {
		t.Fatalf("failed to create default linux SB policy: %v", err)
	}
	pOut := applySecureBootPolicy(sbPolicy, protoSbState)
	if len(pOut.Errors) == 0 {
		t.Error("expected error in policy application when adding db entry")
	}
}

func TestDbxEntryMissingAgainstValidSecureBootPolicyFails(t *testing.T) {
	eventLog, err := attest.ParseEventLog(Debian10GCE.RawLog)
	if err != nil {
		t.Fatalf("failed to parse event log: %v", err)
	}
	events := eventLog.Events(attest.HashSHA1)

	attestSbState, err := attest.ParseSecurebootState(events)
	if err != nil {
		t.Fatalf("failed to parse Secure Boot state: %v", err)
	}

	// Delete a dbx entry.
	attestSbState.ForbiddenHashes = attestSbState.ForbiddenHashes[1:]
	protoSbState, err := convertToProtoSecureBootState(attestSbState)
	if err != nil {
		t.Fatalf("failed to convert SB state to proto: %v", err)
	}

	sbPolicy, err := DefaultGceLinuxSecureBootPolicy()
	if err != nil {
		t.Fatalf("failed to create default linux SB policy: %v", err)
	}
	pOut := applySecureBootPolicy(sbPolicy, protoSbState)
	if len(pOut.Errors) == 0 {
		t.Error("expected error in policy application when adding db entry")
	}
}

func TestPolicyAuthorityEntryMissing(t *testing.T) {
	eventLog, err := attest.ParseEventLog(Debian10GCE.RawLog)
	if err != nil {
		t.Fatalf("failed to parse event log: %v", err)
	}
	events := eventLog.Events(attest.HashSHA1)

	attestSbState, err := attest.ParseSecurebootState(events)
	if err != nil {
		t.Fatalf("failed to parse Secure Boot state: %v", err)
	}
	attestSbState.PreSeparatorAuthority = nil
	attestSbState.PostSeparatorAuthority = nil

	sbPolicy, err := DefaultGceLinuxSecureBootPolicy()
	if err != nil {
		t.Fatalf("failed to create default linux SB policy: %v", err)
	}

	protoSbState, err := convertToProtoSecureBootState(attestSbState)
	if err != nil {
		t.Fatalf("failed to convert SB state to proto: %v", err)
	}
	pOut := applySecureBootPolicy(sbPolicy, protoSbState)
	if len(pOut.Errors) != 0 {
		t.Errorf("expected success on missing authority entries")
	}
}

func TestAuthorityEntryUnknown(t *testing.T) {
	eventLog, err := attest.ParseEventLog(Debian10GCE.RawLog)
	if err != nil {
		t.Fatalf("failed to parse event log: %v", err)
	}
	events := eventLog.Events(attest.HashSHA1)

	attestSbState, err := attest.ParseSecurebootState(events)
	if err != nil {
		t.Fatalf("failed to parse Secure Boot state: %v", err)
	}

	sbPolicy, err := DefaultGceLinuxSecureBootPolicy()
	if err != nil {
		t.Fatalf("failed to create default linux SB policy: %v", err)
	}

	protoSbState, err := convertToProtoSecureBootState(attestSbState)
	if err != nil {
		t.Fatalf("failed to convert SB state to proto: %v", err)
	}

	sbPolicy.PermittedAuthorities = nil
	pOut := applySecureBootPolicy(sbPolicy, protoSbState)
	if len(pOut.Errors) == 0 {
		t.Errorf("expected errors from missing authority entries")
	}
}

func TestUnknownFirmwareVersionFails(t *testing.T) {
	eventLog, err := attest.ParseEventLog(Debian10GCE.RawLog)
	if err != nil {
		t.Fatalf("failed to parse event log: %v", err)
	}
	events := eventLog.Events(attest.HashSHA1)

	platState, err := parsePlatformState(events)
	if err != nil {
		t.Fatalf("failed to parse Platform Config state: %v", err)
	}

	policy, err := DefaultGceLinuxPolicy()
	if err != nil {
		t.Fatalf("failed to create default policy")
	}
	gcePlatPolicy := policy.Platform
	gcePlatPolicy.AllowedFirmwareVersions = nil
	pOut := applyPlatformPolicy(gcePlatPolicy, platState)
	if len(pOut.Errors) == 0 {
		t.Error("expected error in policy application when removing firmware version")
	}
}

func TestPlatformPolicyMinimumConfidentialExceededFails(t *testing.T) {
	eventLog, err := attest.ParseEventLog(Debian10GCE.RawLog)
	if err != nil {
		t.Fatalf("failed to parse event log: %v", err)
	}
	events := eventLog.Events(attest.HashSHA1)

	platState, err := parsePlatformState(events)
	if err != nil {
		t.Fatalf("failed to parse Platform Config state: %v", err)
	}

	policy, err := DefaultGceLinuxPolicy()
	if err != nil {
		t.Fatalf("failed to create default policy")
	}
	gcePlatPolicy := policy.Platform
	gcePlatPolicy.MinimumTechnology = tpmpb.GceConfidentialTechnology_AMD_SEV
	pOut := applyPlatformPolicy(gcePlatPolicy, platState)
	if len(pOut.Errors) == 0 {
		t.Error("expected error when applying minimum SEV ConfTech to nonconfidential instance event log")
	}
}

func getGceMemoryEncryptionNonhostEvent(memoryEncrypted bool) []byte {
	event := make([]byte, 32)
	copy(event[:], []byte(GceMemoryEncryptionSignature))
	// event[15] is a null byte.
	if memoryEncrypted {
		event[16] = 0x01
	}
	// Last 15 bytes are reserved.
	return event
}

func (pOut *PolicyCheckOutput) assertNoIssues(t *testing.T) {
	if len(pOut.Errors) != 0 {
		t.Errorf("failed to apply policy: %v", pOut.Errors)
	}
}
