package server

import _ "embed" // Necessary to use go:embed

// Expected Firmware/PCR0 Event Types.
//
// Taken from TCG PC Client Platform Firmware Profile Specification,
// Table 14 Events.
const (
	NoAction     uint32 = 0x00000003
	Separator    uint32 = 0x00000004
	SCRTMVersion uint32 = 0x00000008
	NonhostInfo  uint32 = 0x00000011
)

var (
	// GCENonHostInfoSignature identifies the GCE Non-Host info event, which
	// indicates if memory encryption is enabled. This event is 32-bytes consisting
	// of the below signature (16 bytes), followed by a byte indicating whether
	// it is confidential, followed by 15 reserved bytes.
	GCENonHostInfoSignature = []byte("GCE NonHostInfo\x00")
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
