package server

import _ "embed" // Necessary to use go:embed

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
