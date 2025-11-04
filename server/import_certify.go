package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"

	tpb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/tpm2"
)

// This file aims to implement the verifier side of https://trustedcomputinggroup.org/wp-content/uploads/EK-Based-Key-Attestation-with-TPM-Firmware-Version-V1-RC1_9July2025.pdf#page=8
// For reference: https://github.com/TrustedComputingGroup/tpm-fw-attestation-reference-code

var (
	errCertifiedWrongName = errors.New("incorrect name")
	errWrongHashAlg       = errors.New("wrong hash algorithm")
	errInvalidHMAC        = errors.New("invalid HMAC")
	errInvalidAttestation = errors.New("attestation statement was invalid")
)

// CreateRestrictedHMACBlob generates a new HMAC key and wraps it to the given EK.
func CreateRestrictedHMACBlob(tPublic *tpm2.TPMTPublic) (*tpb.ImportBlob, []byte, error) {
	encap, err := tpm2.ImportEncapsulationKey(tPublic)
	if err != nil {
		return nil, nil, err
	}

	hmacKey := make([]byte, 32)
	pub, sensitive := generateRestrictedHMACKey(hmacKey)
	name, err := tpm2.ObjectName(pub)
	if err != nil {
		return nil, nil, err
	}

	duplicate, inSymSeed, err := tpm2.CreateDuplicate(rand.Reader, encap, name.Buffer, tpm2.Marshal(sensitive))
	if err != nil {
		return nil, nil, err
	}

	return &tpb.ImportBlob{
		PublicArea:    tpm2.Marshal(pub),
		Duplicate:     duplicate,
		EncryptedSeed: inSymSeed,
	}, hmacKey, nil
}

// VerifyCertifiedAKBlob verifies the blob against a secret HMAC.
func VerifyCertifiedAKBlob(req *tpb.CertifiedBlob, secret []byte) error {
	akPub, err := tpm2.Unmarshal[tpm2.TPMTPublic](req.GetPubArea())
	if err != nil {
		return err
	}

	akName, err := tpm2.ObjectName(akPub)
	if err != nil {
		return err
	}

	signature, err := tpm2.Unmarshal[tpm2.TPMTSignature](req.GetRawSig())
	if err != nil {
		return err
	}

	hmac, err := signature.Signature.HMAC()
	if err != nil {
		return err
	}

	if err := verifyHMAC(secret, req.GetCertifyInfo(), hmac); err != nil {
		return err
	}

	attest, err := tpm2.Unmarshal[tpm2.TPMSAttest](req.GetCertifyInfo())
	if err != nil {
		return err
	}

	if err := verifyAttestCertify(attest); err != nil {
		return err
	}

	certify, err := attest.Attested.Certify()
	if err != nil {
		return err
	}

	if err := verifyCertifyInfo(akName, certify); err != nil {
		return err
	}

	return nil
}

// generateRestrictedHMACKey writes a new hmac to the input parameter and produces the pub/priv tpm2 structures
func generateRestrictedHMACKey(hmacKey []byte) (*tpm2.TPMTPublic, *tpm2.TPMTSensitive) {
	// Generate the random obfuscation value and key
	obfuscate := make([]byte, 32)
	rand.Read(obfuscate)
	rand.Read(hmacKey[:])

	// Unique for a KEYEDHASH object is H_nameAlg(obfuscate | key)
	// See Part 1, "Public Area Creation"
	h := sha256.New()
	h.Write(obfuscate)
	h.Write(hmacKey[:])

	pub := &tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			UserWithAuth: true,
			NoDA:         true,
			Restricted:   true,
			SignEncrypt:  true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{
			Scheme: tpm2.TPMTKeyedHashScheme{
				Scheme: tpm2.TPMAlgHMAC,
				Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC, &tpm2.TPMSSchemeHMAC{
					HashAlg: tpm2.TPMAlgSHA256,
				}),
			},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgKeyedHash, &tpm2.TPM2BDigest{
			Buffer: h.Sum(nil),
		}),
	}

	priv := &tpm2.TPMTSensitive{
		SensitiveType: tpm2.TPMAlgKeyedHash,
		SeedValue: tpm2.TPM2BDigest{
			Buffer: obfuscate,
		},
		Sensitive: tpm2.NewTPMUSensitiveComposite(tpm2.TPMAlgKeyedHash, &tpm2.TPM2BSensitiveData{
			Buffer: hmacKey[:],
		}),
	}

	return pub, priv
}

// verifyHMAC checks the MAC on the given message.
func verifyHMAC(hmacKey []byte, message []byte, ha *tpm2.TPMTHA) error {
	if ha.HashAlg != tpm2.TPMAlgSHA256 {
		return fmt.Errorf("%w %v (expected SHA256)", errWrongHashAlg, ha.HashAlg)
	}
	digest := sha256.Sum256(message)
	h := hmac.New(sha256.New, hmacKey[:])
	h.Write(digest[:])
	if subtle.ConstantTimeCompare(ha.Digest, h.Sum(nil)) != 1 {
		return errInvalidHMAC
	}
	return nil
}

// verifyAttestCertify checks that the attestation structure has valid data
func verifyAttestCertify(attest *tpm2.TPMSAttest) error {
	if attest.Type != tpm2.TPMSTAttestCertify {
		return fmt.Errorf("expected attest type TPMSTAttestCertify, got %v", attest.Type)
	}
	if attest.Magic != tpm2.TPMGeneratedValue {
		return fmt.Errorf("%w: unexpected prefix %0x", errInvalidAttestation, attest.Magic)
	}

	return nil
}

// verifyCertifyInfo checks the certifyInfo against the given name.
func verifyCertifyInfo(name *tpm2.TPM2BName, certifyInfo *tpm2.TPMSCertifyInfo) error {
	// Check that the certified Name is the same as we expected.
	if !bytes.Equal(name.Buffer, certifyInfo.Name.Buffer) {
		return fmt.Errorf("%w: expected Name %x, certified Name was %x", errCertifiedWrongName, name.Buffer, certifyInfo.Name.Buffer)
	}

	// We can't really check the QualifiedName here, since we don't have any
	// information about the object's parent. As a paranoid consistency check,
	// just make sure that QualifiedName doesn't match Name for some reason.
	if bytes.Equal(certifyInfo.QualifiedName.Buffer, certifyInfo.Name.Buffer) {
		return fmt.Errorf("%w: QualifiedName unexpectedly matched Name", errCertifiedWrongName)
	}

	return nil
}
