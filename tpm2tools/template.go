package tpm2tools

import (
	"crypto/sha256"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// Calculations from Credential_Profile_EK_V2.0, section 2.1.5.3 - authPolicy
func defaultAuthPolicy() []byte {
	buf, err := tpmutil.Pack(tpm2.CmdPolicySecret, tpm2.HandleEndorsement)
	if err != nil {
		panic(err)
	}
	digest1 := sha256.Sum256(append(make([]byte, 32), buf...))
	// We would normally append the policy buffer to digest1, but the
	// policy buffer is empty for the deafult Auth Policy.
	digest2 := sha256.Sum256(digest1[:])
	return digest2[:]
}

// DefaultEKTemplateRSA returns the default Endorsement Key (EK) template as
// specified in Credential_Profile_EK_V2.0, section 2.1.5.1 - authPolicy.
// https://trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf
func DefaultEKTemplateRSA() tpm2.Public {
	return tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagAdminWithPolicy | tpm2.FlagRestricted | tpm2.FlagDecrypt,
		AuthPolicy: defaultAuthPolicy(),
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:    2048,
			Exponent:   0,
			ModulusRaw: make([]byte, 256), // public.unique must be all zeros
		},
	}
}

// AIKTemplateRSA returns a potential Attestation Identity Key (AIK) template.
// This is very similar to DefaultEKTemplateRSA, except that this will be a
// signing key instead of an encrypting key. The random nonce provided allows
// for multiple AIKs to easily cooexist on the same TPM (which only has 1 EK).
func AIKTemplateRSA(nonce [256]byte) tpm2.Public {
	return tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagSignerDefault,
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits:    2048,
			Exponent:   0,
			ModulusRaw: nonce[:], // Use public.unique to generate distinct keys
		},
	}
}

// SRKTemplateRSA returns a sane Storage Root Key (SRK) template.
// This is based upon the advice in the TCG's TPM v2.0 Provisioning Guidance.
func SRKTemplateRSA() tpm2.Public {
	template := DefaultEKTemplateRSA()
	template.Attributes |= tpm2.FlagUserWithAuth
	template.Attributes &= ^tpm2.FlagAdminWithPolicy
	template.Attributes |= tpm2.FlagNoDA

	template.AuthPolicy = nil

	return template
}
