package server

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/credactivation"
)

// EncryptedCredential represents encrypted parameters which must be activated
// against a key.
type EncryptedCredential struct {
	Credential []byte
	Secret     []byte
}

// ActivationParameters encapsulates the inputs for activating an AK.
type ActivationParameters struct {
	// The activation key, an assymetric key that is permanently bound
	// to the TPM.
	//
	// This is typically the endorsement key, or EK.
	//
	// Activation will verify that the provided key is held on the same
	// TPM as the anchor key. However, it is the caller's responsibility to
	// ensure the activation key they provide corresponds to the
	// device which they are trying to associate the anchor key with.
	EK crypto.PublicKey

	// The anchor key to be activated.

	// This is typically the Attestation Key, or AK.
	//  describes the properties of
	// an asymmetric key (managed by the TPM) which signs attestation
	// structures.
	// The values from this structure can be obtained by calling
	// Parameters() on an attest.AK.
	AK AttestationParameters

	// Rand is a source of randomness to generate a seed and secret for the
	// challenge.
	//
	// If nil, this defaults to crypto.Rand.
	Rand io.Reader
}

// AttestationParameters describes information about a key which is necessary
// for verifying its properties remotely.
type AttestationParameters struct {
	// Public represents the AK's canonical encoding. This blob includes the
	// public key, as well as signing parameters such as the hash algorithm
	// used to generate quotes.
	//
	// For TPM 2.0 devices, Public is encoded as a TPMT_PUBLIC structure
	// described in the TPM Part 2 Structures specification, available at
	// https://trustedcomputinggroup.org/wp-content/uploads/TPM-Main-Part-2-TPM-Structures_v1.2_rev116_01032011.pdf
	//
	// Subsequent fields are only populated for AKs generated on a TPM
	// implementing version 2.0 of the specification. The specific structures
	// referenced for each field are defined in the TPM Revision 2, Part 2 -
	// Structures specification, available here:
	// https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
	Public []byte

	// KeyCreationData
	// implementing version 2.0 of the specification. The specific structures
	KeyCreationData client.KeyCreationData
}

// GenerateChallenge returns a credential activation challenge, which can be provided
// to the TPM to verify that a key's parameters are authentic and that the key
// is present on the same TPM as the EK.
//
// The caller is expected to verify the secret returned from the TPM as
// as result of calling ActivateCredential() matches the secret returned here.
// The caller should use subtle.ConstantTimeCompare to avoid potential
// timing attack vectors.
//
// Activation will verify that the provided key is held on the same
// TPM as the anchor key. However, it is the caller's responsibility to
// ensure the activation key they provide corresponds to the
// device which they are trying to associate the anchor key with.

func GenerateChallenge(rng io.Reader, ekPub crypto.PublicKey) (secret []byte, ec *EncryptedCredential, err error) {
	if err := checkKeyParameters(); err != nil {
		return nil, nil, err
	}

	if rng == nil {
		rng = rand.Reader
	}

	att, err := tpm2.DecodeAttestationData(p.AK.CreateAttestation)
	if err != nil {
		return nil, fmt.Errorf("DecodeAttestationData() failed: %v", err)
	}
	cred, encSecret, err := credactivation.Generate(att.AttestedCreationInfo.Name.Digest, p.EK, symBlockSize, secret)
	if err != nil {
		return nil, fmt.Errorf("credactivation.Generate() failed: %v", err)
	}

	return &EncryptedCredential{
		Credential: cred,
		Secret:     encSecret,
	}, nil
}

func checkKeyParameters() error {
	if len(p.AK.CreateSignature) < 8 {
		return fmt.Errorf("signature is too short to be valid: only %d bytes", len(p.AK.CreateSignature))
	}

	pub, err := tpm2.DecodePublic(p.AK.Public)
	if err != nil {
		return fmt.Errorf("DecodePublic() failed: %v", err)
	}
	_, err = tpm2.DecodeCreationData(p.AK.CreateData)
	if err != nil {
		return fmt.Errorf("DecodeCreationData() failed: %v", err)
	}
	att, err := tpm2.DecodeAttestationData(p.AK.CreateAttestation)
	if err != nil {
		return fmt.Errorf("DecodeAttestationData() failed: %v", err)
	}
	if att.Type != tpm2.TagAttestCreation {
		return fmt.Errorf("attestation does not apply to creation data, got tag %x", att.Type)
	}

	// TODO: Support ECC AKs.
	switch pub.Type {
	case tpm2.AlgRSA:
		if pub.RSAParameters.KeyBits < minRSABits {
			return fmt.Errorf("attestation key too small: must be at least %d bits but was %d bits", minRSABits, pub.RSAParameters.KeyBits)
		}
	default:
		return fmt.Errorf("public key of alg 0x%x not supported", pub.Type)
	}

	// Compute & verify that the creation data matches the digest in the
	// attestation structure.
	nameHash, err := pub.NameAlg.Hash()
	if err != nil {
		return fmt.Errorf("HashConstructor() failed: %v", err)
	}
	h := nameHash.New()
	h.Write(p.AK.CreateData)
	if !bytes.Equal(att.AttestedCreationInfo.OpaqueDigest, h.Sum(nil)) {
		return errors.New("attestation refers to different public key")
	}

	// Make sure the AK has sane key parameters (Attestation can be faked if an AK
	// can be used for arbitrary signatures).
	// We verify the following:
	// - Key is TPM backed.
	// - Key is TPM generated.
	// - Key is a restricted key (means it cannot do arbitrary signing/decrypt ops).
	// - Key cannot be duplicated.
	// - Key was generated by a call to TPM_Create*.
	if att.Magic != tpm20GeneratedMagic {
		return errors.New("creation attestation was not produced by a TPM")
	}
	if (pub.Attributes & tpm2.FlagFixedTPM) == 0 {
		return errors.New("AK is exportable")
	}
	if ((pub.Attributes & tpm2.FlagRestricted) == 0) || ((pub.Attributes & tpm2.FlagFixedParent) == 0) || ((pub.Attributes & tpm2.FlagSensitiveDataOrigin) == 0) {
		return errors.New("provided key is not limited to attestation")
	}

	// Verify the attested creation name matches what is computed from
	// the public key.
	match, err := att.AttestedCreationInfo.Name.MatchesPublic(pub)
	if err != nil {
		return err
	}
	if !match {
		return errors.New("creation attestation refers to a different key")
	}

	// Check the signature over the attestation data verifies correctly.
	pk := rsa.PublicKey{E: int(pub.RSAParameters.Exponent()), N: pub.RSAParameters.Modulus()}
	signHash, err := pub.RSAParameters.Sign.Hash.Hash()
	if err != nil {
		return err
	}
	hsh := signHash.New()
	hsh.Write(p.AK.CreateAttestation)
	verifyHash, err := pub.RSAParameters.Sign.Hash.Hash()
	if err != nil {
		return err
	}

	if len(p.AK.CreateSignature) < 8 {
		return fmt.Errorf("signature invalid: length of %d is shorter than 8", len(p.AK.CreateSignature))
	}

	sig, err := tpm2.DecodeSignature(bytes.NewBuffer(p.AK.CreateSignature))
	if err != nil {
		return fmt.Errorf("DecodeSignature() failed: %v", err)
	}

	if err := rsa.VerifyPKCS1v15(&pk, verifyHash, hsh.Sum(nil), sig.RSA.Signature); err != nil {
		return fmt.Errorf("could not verify attestation: %v", err)
	}

	return nil
}
