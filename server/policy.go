package server

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"unicode/utf16"

	tpmpb "github.com/google/go-tpm-tools/proto"
)

// PolicyCheckOutput represents the errors found when applying
// an AttestationPolicy to a MachineState.
type PolicyCheckOutput struct {
	Errors []error
}

func (pOut PolicyCheckOutput) merge(pOuts ...PolicyCheckOutput) PolicyCheckOutput {
	for _, toMerge := range pOuts {
		pOut.Errors = append(pOut.Errors, toMerge.Errors...)
	}
	return pOut
}

// ValidateAttestationPolicy determines whether an AttestationPolicy
// is written in a way that the policy could never pass. Validate
// returns an error of type PolicyCheckError.
func ValidateAttestationPolicy(policy *tpmpb.AttestationPolicy) PolicyCheckOutput {
	var ret PolicyCheckOutput
	platErr := validatePlatformPolicy(policy.Platform)
	sbErr := validateSecureBootPolicy(policy.SecureBoot)

	ret = ret.merge(platErr, sbErr)
	return ret
}

// ApplyAttestationPolicy takes a MachineState and verifies it
// against the AttestationPolicy. If verification fails, Apply
// returns a high-level error (of type PolicyCheckError) with
// sub-errors.
//
// It is the caller's responsibility to verify the event log
// against a TPM quote.
func ApplyAttestationPolicy(policy *tpmpb.AttestationPolicy, state *tpmpb.MachineState) PolicyCheckOutput {
	// Early return on validation errors.
	if pOut := ValidateAttestationPolicy(policy); len(pOut.Errors) != 0 {
		return pOut
	}

	var ret PolicyCheckOutput
	platErr := applyPlatformPolicy(policy.Platform, state.Platform)

	sbErr := applySecureBootPolicy(policy.SecureBoot, state.SecureBoot)
	ret = ret.merge(platErr, sbErr)
	return ret
}

func validateSecureBootPolicy(sbPolicy *tpmpb.SecureBootPolicy) PolicyCheckOutput {
	var ret PolicyCheckOutput
	if sbPolicy == nil || sbPolicy.Permitted == nil || sbPolicy.Forbidden == nil {
		return ret
	}
	if len(sbPolicy.Permitted.Certs) == 0 && len(sbPolicy.Permitted.Hashes) == 0 {
		ret.Errors = append(ret.Errors, errors.New("invalid policy: db unspecified"))
	}
	if len(sbPolicy.Forbidden.Certs) == 0 && len(sbPolicy.Forbidden.Hashes) == 0 {
		ret.Errors = append(ret.Errors, errors.New("invalid policy: dbx unspecified"))
	}
	if len(sbPolicy.PermittedAuthorities) == 0 {
		ret.Errors = append(ret.Errors, errors.New("invalid policy: authority entries unspecified"))
	}
	return ret
}

func applySecureBootPolicy(sbPolicy *tpmpb.SecureBootPolicy, sbState *tpmpb.SecureBootState) PolicyCheckOutput {
	var ret PolicyCheckOutput
	if sbPolicy == nil {
		return ret
	}

	if !sbState.Enabled {
		ret.Errors = append(ret.Errors, errors.New("policy check failed: Secure Boot not enabled"))
	}

	diff := sbState.Db.SetDifference(sbPolicy.Permitted)
	if !diff.IsEmpty() {
		ret.Errors = append(ret.Errors, fmt.Errorf("policy check failed: found %v db entries not specified in policy", diff.Size()))
	}
	diff = sbPolicy.Forbidden.SetDifference(sbState.Dbx)
	if !diff.IsEmpty() {
		ret.Errors = append(ret.Errors, fmt.Errorf("policy check failed: found %v dbx entries not specified in policy", diff.Size()))
	}
	certDiff := tpmpb.SetDifference(sbState.Authority.Certs, sbPolicy.PermittedAuthorities)
	if len(certDiff) != 0 {
		ret.Errors = append(ret.Errors, fmt.Errorf("policy check failed: found %v authority entries not specified in policy", len(certDiff)))
	}

	return ret
}

func validatePlatformPolicy(platPolicy *tpmpb.PlatformPolicy) PolicyCheckOutput {
	var ret PolicyCheckOutput
	if platPolicy == nil {
		return ret
	}
	if len(platPolicy.AllowedFirmwareVersions) == 0 {
		ret.Errors = append(ret.Errors, errors.New("invalid policy: expected at least one allowed firmware version"))
	}
	return ret
}

func applyPlatformPolicy(platPolicy *tpmpb.PlatformPolicy, platformState *tpmpb.PlatformState) PolicyCheckOutput {
	var ret PolicyCheckOutput
	if platPolicy == nil {
		return ret
	}
	pOut := applyFirmwareVersionCheck(platPolicy, platformState.FirmwareVersion)
	ret = ret.merge(pOut)

	if platPolicy.MinimumTechnology > platformState.Technology {
		ret.Errors = append(ret.Errors, fmt.Errorf("policy check failed: current ConfidentialTechnology setting %v does not meet the minimum required %v",
			platformState.Technology, platPolicy.MinimumTechnology))
	}
	return ret
}

func applyFirmwareVersionCheck(platPolicy *tpmpb.PlatformPolicy, firmwareVersion []byte) PolicyCheckOutput {
	var ret PolicyCheckOutput
	for _, allowedSCRTMVersion := range platPolicy.AllowedFirmwareVersions {
		if bytes.Equal(firmwareVersion, allowedSCRTMVersion) {
			return ret
		}
	}
	ret.Errors = []error{fmt.Errorf("policy check failed: no matching firmware version based on PlatformPolicy")}
	return ret
}

// CommonDbContents contains the two certs regularly in the UEFI Secure Boot db:
// - Microsoft Corporation UEFI CA 2011
// - Microsoft Windows Production PCA 2011
func CommonDbContents() *tpmpb.Database {
	return &tpmpb.Database{
		Certs: []*tpmpb.Certificate{
			{
				Der: MicrosoftUEFICA2011Cert,
			},
			{
				Der: WindowsProductionPCA2011Cert,
			},
		},
	}
}

// CommonDbxContents takes a dbxHexList and returns an expected dbx Database.
// The dbxHexList should be one of the curated lists in policy_constants.go.
//
// These are taken from the UEFI revocation
// list file site. The dbx also contains two revoked certs from Debian and
// Canonical due to the Boothole
// (https://eclypsium.com/2020/07/29/theres-a-hole-in-the-boot/)
// vulnerability.
func CommonDbxContents(dbxHexList []string) (*tpmpb.Database, error) {
	dbxBytes := make([][]byte, 0, len(dbxHexList))
	for _, hash := range dbxHexList {
		bytes, err := hex.DecodeString(hash)
		if err != nil {
			return nil, fmt.Errorf("failed to decode hash in dbx list: %v", err)
		}
		dbxBytes = append(dbxBytes, bytes)
	}
	return &tpmpb.Database{
		Certs: []*tpmpb.Certificate{
			{
				Der: RevokedCanonicalBootholeCert,
			},
			{
				Der: RevokedDebianBootholeCert,
			},
		},
		Hashes: dbxBytes,
	}, nil
}

// CommonGceDbxContents adds a revoked Cisco Virtual UEFI CA to the
// CommonDbxContents, seen on GCE machines.
func CommonGceDbxContents(dbxHexList []string) (*tpmpb.Database, error) {
	dbx, err := CommonDbxContents(dbxHexList)
	if err != nil {
		return nil, err
	}
	dbx.Certs = append(dbx.Certs,
		&tpmpb.Certificate{
			Der: RevokedCiscoCert,
		})
	return dbx, nil
}

// DefaultGceSecureBootPolicy returns a partial GCE secure boot policy.
// Specifically, the policy specifies a:
// - db
// - dbx
// - Authorities
//
// It is missing distro-specific CAs used with shim (e.g., the Canonical
// CA for Ubuntu).
func DefaultGceSecureBootPolicy() (*tpmpb.SecureBootPolicy, error) {
	dbx, err := CommonGceDbxContents(DbxX64ListOct2020Contents)
	if err != nil {
		return nil, err
	}
	return &tpmpb.SecureBootPolicy{
		Permitted: CommonDbContents(),
		Forbidden: dbx,
	}, nil
}

// DefaultGceLinuxSecureBootPolicy returns a partial GCE AttestationPolicy.
// Specifically, the policy contains a:
// - PlatformPolicy with known values for GCE firmware versions
// - GCE's default Secure Boot policy.
//
// It is missing distro-specific CAs used with shim (e.g., the Canonical
// CA for Ubuntu).
func DefaultGceLinuxSecureBootPolicy() (*tpmpb.SecureBootPolicy, error) {
	secureBootPolicy, err := DefaultGceSecureBootPolicy()
	if err != nil {
		return nil, err
	}
	secureBootPolicy.PermittedAuthorities = []*tpmpb.Certificate{
		{
			Der: MicrosoftUEFICA2011Cert,
		},
	}
	return secureBootPolicy, nil
}

// DefaultGceLinuxPolicy returns an AttestationPolicy that
// corresponds to a new image on GCE.
//
// The default is an incomplete policy, as Linux-based images
// extend more authority entries via the shim. Applying a policy
// without shim authority entries will return an error in
// PolicyCheckOutput.
func DefaultGceLinuxPolicy() (*tpmpb.AttestationPolicy, error) {
	sbPolicy, err := DefaultGceLinuxSecureBootPolicy()
	if err != nil {
		return nil, fmt.Errorf("failed to construct attestation policy: %v", err)
	}
	return &tpmpb.AttestationPolicy{
		Platform: &tpmpb.PlatformPolicy{
			AllowedFirmwareVersions: [][]byte{getGceVirtualFirmwareEvent(0), getGceVirtualFirmwareEvent(1)},
			MinimumTechnology:       tpmpb.GceConfidentialTechnology_NONE,
		},
		SecureBoot: sbPolicy,
	}, nil
}

func getGceVirtualFirmwareEvent(version uint) []byte {
	if version == 0 {
		return []byte{0x00, 0x00, 0x00, 0x00}
	}
	event := GceVirtualFirmwareVersion
	// Add version information in UCS-2 format.
	versionString := strconv.Itoa(int(version))
	encoded := utf16.Encode([]rune(versionString))
	encodedBytes := make([]byte, 2)
	for _, encodedRune := range encoded {
		binary.LittleEndian.PutUint16(encodedBytes, encodedRune)
		event = append(event, encodedBytes...)
	}

	// Add null terminator.
	event = append(event, 0x00, 0x00)
	return event
}
