package server

import (
	"bytes"
	"crypto/x509"
	_ "embed" // Necessary to use go:embed
	"errors"
	"fmt"
	"strconv"

	pb "github.com/google/go-tpm-tools/proto/attest"
)

// Expected TCG Event Log Event Types.
//
// Taken from TCG PC Client Platform Firmware Profile Specification,
// Table 14 Events.
const (
	NoAction                   uint32 = 0x00000003
	Separator                  uint32 = 0x00000004
	SCRTMVersion               uint32 = 0x00000008
	IPL                        uint32 = 0x0000000D
	NonhostInfo                uint32 = 0x00000011
	EFIBootServicesApplication uint32 = 0x80000003
	EFIAction                  uint32 = 0x80000007
)

// Constant events used with type "EV_EFI_ACTION".
// Taken from TCG PC Client Platform Firmware Profile Specification,
// Table 17 EV_EFI_ACTION Strings.
const (
	// Measured when Boot Manager attempts to execute code from a Boot Option.
	CallingEFIApplication      string = "Calling EFI Application from Boot Option"
	ExitBootServicesInvocation string = "Exit Boot Services Invocation"
)

var (
	// GCENonHostInfoSignature identifies the GCE Non-Host info event, which
	// indicates if memory encryption is enabled. This event is 32-bytes consisting
	// of the below signature (16 bytes), followed by a byte indicating whether
	// it is confidential, followed by 15 reserved bytes.
	GCENonHostInfoSignature = []byte("GCE NonHostInfo\x00")
	// GceVirtualFirmwarePrefix is the little-endian UCS-2 encoded string
	// "GCE Virtual Firmware v" without a null terminator. All GCE firmware
	// versions are UCS-2 encoded, start with this prefix, contain the firmware
	// version encoded as an integer, and end with a null terminator.
	GceVirtualFirmwarePrefix = []byte{0x47, 0x00, 0x43, 0x00,
		0x45, 0x00, 0x20, 0x00, 0x56, 0x00, 0x69, 0x00, 0x72, 0x00,
		0x74, 0x00, 0x75, 0x00, 0x61, 0x00, 0x6c, 0x00, 0x20, 0x00,
		0x46, 0x00, 0x69, 0x00, 0x72, 0x00, 0x6d, 0x00, 0x77, 0x00,
		0x61, 0x00, 0x72, 0x00, 0x65, 0x00, 0x20, 0x00, 0x76, 0x00}
)

// Standard Secure Boot certificates (DER encoded)
var (
	//go:embed secure-boot/GcePk.crt
	GceDefaultPKCert []byte
	//go:embed secure-boot/MicCorKEKCA2011_2011-06-24.crt
	MicrosoftKEKCA2011Cert []byte
	//go:embed secure-boot/MicWinProPCA2011_2011-10-19.crt
	WindowsProductionPCA2011Cert []byte
	//go:embed secure-boot/MicCorUEFCA2011_2011-06-27.crt
	MicrosoftUEFICA2011Cert []byte
)

// Revoked Signing certificates (DER encoded)
var (
	//go:embed secure-boot/canonical-boothole.crt
	RevokedCanonicalBootholeCert []byte
	//go:embed secure-boot/debian-boothole.crt
	RevokedDebianBootholeCert []byte
	//go:embed secure-boot/cisco-boothole.crt
	RevokedCiscoCert []byte
)

// Known Privacy CA certs.
var (
	//go:embed ca-certs/tpm_ek_root_1.cer
	gceEKRootCA []byte
	//go:embed ca-certs/tpm_ek_intermediate_2.crt
	gceEKIntermediateCA2 []byte
)

// Certificates corresponding to the known CA certs for GCE.
var (
	GceEKRoots         []*x509.Certificate
	GceEKIntermediates []*x509.Certificate
)

func init() {
	var err error
	GceEKRoots, err = parseCerts([][]byte{gceEKRootCA})
	if err != nil {
		panic(fmt.Sprintf("failed to create the root cert pool: %v", err))
	}
	GceEKIntermediates, err = parseCerts([][]byte{gceEKIntermediateCA2})
	if err != nil {
		panic(fmt.Sprintf("failed to create the intermediate cert pool: %v", err))
	}
}

func parseCerts(rawCerts [][]byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, len(rawCerts))
	for i, certBytes := range rawCerts {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse cert: %w", err)
		}
		certs[i] = cert
	}
	return certs, nil
}

// ConvertSCRTMVersionToGCEFirmwareVersion attempts to parse the Firmware
// Version of a GCE VM from the bytes of the version string of the SCRTM. This
// data should come from a valid and verified EV_S_CRTM_VERSION event.
func ConvertSCRTMVersionToGCEFirmwareVersion(version []byte) (uint32, error) {
	prefixLen := len(GceVirtualFirmwarePrefix)
	if (len(version) <= prefixLen) || (len(version)%2 != 0) {
		return 0, fmt.Errorf("length of GCE version (%d) is invalid", len(version))
	}
	if !bytes.Equal(version[:prefixLen], GceVirtualFirmwarePrefix) {
		return 0, errors.New("prefix for GCE version is missing")
	}
	asciiVersion := []byte{}
	for i, b := range version[prefixLen:] {
		// Skip the UCS-2 null bytes and the null terminator
		if b == '\x00' {
			continue
		}
		// All odd bytes in our UCS-2 string should be Null
		if i%2 != 0 {
			return 0, errors.New("invalid UCS-2 in the version string")
		}
		asciiVersion = append(asciiVersion, b)
	}

	versionNum, err := strconv.Atoi(string(asciiVersion))
	if err != nil {
		return 0, fmt.Errorf("when parsing GCE firmware version: %w", err)
	}
	return uint32(versionNum), nil
}

// ConvertGCEFirmwareVersionToSCRTMVersion creates the corresponding SCRTM
// version string from a numerical GCE firmware version. The returned string
// is UCS2 encoded with a null terminator. A version of 0 corresponds to an
// empty string (representing old GCE VMs that just used an empty string).
func ConvertGCEFirmwareVersionToSCRTMVersion(version uint32) []byte {
	if version == 0 {
		return []byte{}
	}
	versionString := GceVirtualFirmwarePrefix
	for _, b := range []byte(strconv.Itoa(int(version))) {
		// Convert ACSII to little-endian UCS-2
		versionString = append(versionString, b, 0)
	}
	// Add the null terminator
	return append(versionString, 0, 0)
}

// ParseGCENonHostInfo attempts to parse the Confidential VM
// technology used by a GCE VM from the GCE Non-Host info event. This data
// should come from a valid and verified EV_NONHOST_INFO event.
func ParseGCENonHostInfo(nonHostInfo []byte) (pb.GCEConfidentialTechnology, error) {
	prefixLen := len(GCENonHostInfoSignature)
	if len(nonHostInfo) < (prefixLen + 1) {
		return pb.GCEConfidentialTechnology_NONE, fmt.Errorf("length of GCE Non-Host info (%d) is too short", len(nonHostInfo))
	}

	if !bytes.Equal(nonHostInfo[:prefixLen], GCENonHostInfoSignature) {
		return pb.GCEConfidentialTechnology_NONE, errors.New("prefix for GCE Non-Host info is missing")
	}
	tech := nonHostInfo[prefixLen]
	if tech > byte(pb.GCEConfidentialTechnology_AMD_SEV_SNP) {
		return pb.GCEConfidentialTechnology_NONE, fmt.Errorf("unknown GCE Confidential Technology: %d", tech)
	}
	return pb.GCEConfidentialTechnology(tech), nil
}
