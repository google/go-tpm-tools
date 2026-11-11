// Copyright (c) 2018, Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package activate implements generation of data blobs to be used
// when invoking the ActivateCredential command, on a TPM.
package activate

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"

	"github.com/google/go-tpm-tools/tools"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// Labels for use in key derivation or OAEP encryption.
const (
	labelIdentity  = "IDENTITY"
	labelStorage   = "STORAGE"
	labelIntegrity = "INTEGRITY"
)

// ServerGenerate returns a TPM2B_ID_OBJECT & TPM2B_ENCRYPTED_SECRET for use in
// credential activation.
// This has been tested on EKs compliant with TCG 2.0 EK Credential Profile
// specification, revision 14.
// The pub parameter must be a pointer to rsa.PublicKey.
// The secret parameter must not be longer than the longest digest size implemented
// by the TPM. A 32 byte secret is a safe, recommended default.
//
// This function implements Credential Protection as defined in section 24 of the TPM
// specification revision 2 part 1, with the additional caveat of not supporting ECC EKs.
// See: https://trustedcomputinggroup.org/resource/tpm-library-specification/
func ServerGenerate(aik *tpm2.HashValue, pub crypto.PublicKey, secret []byte) ([]byte, []byte, error) {
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("only RSA public keys are supported for credential activation")
	}

	return generateRSA(aik, rsaPub, secret, rand.Reader)
}

func generateRSA(aik *tpm2.HashValue, pub *rsa.PublicKey, secret []byte, rnd io.Reader) ([]byte, []byte, error) {
	hashNew, err := aik.Alg.HashConstructor()
	if err != nil {
		return nil, nil, err
	}

	// The seed length should match the keysize used by the EKs symmetric cipher.
	// For typical RSA EKs, this will be 128 bits (16 bytes).
	// Spec: TCG 2.0 EK Credential Profile revision 14, section 2.1.5.1.
	seed := make([]byte, tools.DefaultEKTemplateRSA().RSAParameters.Symmetric.KeyBits/8)
	if _, err := io.ReadFull(rnd, seed); err != nil {
		return nil, nil, fmt.Errorf("generating seed: %v", err)
	}

	// Encrypt the seed value using the provided public key.
	// See annex B, section 10.4 of the TPM specification revision 2 part 1.
	label := append([]byte(labelIdentity), 0)
	encSecret, err := rsa.EncryptOAEP(hashNew(), rnd, pub, seed, label)
	if err != nil {
		return nil, nil, fmt.Errorf("generating encrypted seed: %v", err)
	}

	// Generate the encrypted credential by convolving the seed with the digest of
	// the AIK, and using the result as the key to encrypt the secret.
	// See section 24.4 of TPM 2.0 specification, part 1.
	aikNameEncoded, err := aik.Encode()
	if err != nil {
		return nil, nil, fmt.Errorf("encoding aikName: %v", err)
	}
	symmetricKey, err := tpm2.KDFa(aik.Alg, seed, labelStorage, aikNameEncoded, nil, len(seed)*8)
	if err != nil {
		return nil, nil, fmt.Errorf("generating symmetric key: %v", err)
	}
	c, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, nil, fmt.Errorf("symmetric cipher setup: %v", err)
	}
	cv, err := tpmutil.Pack(secret)
	if err != nil {
		return nil, nil, fmt.Errorf("generating cv (TPM2B_Digest): %v", err)
	}

	// IV is all null bytes. encIdentity represents the encrypted credential.
	encIdentity := make([]byte, len(cv))
	cipher.NewCFBEncrypter(c, make([]byte, len(symmetricKey))).XORKeyStream(encIdentity, cv)

	// Generate the integrity HMAC, which is used to protect the integrity of the
	// encrypted structure.
	// See section 24.5 of the TPM specification revision 2 part 1.
	macKey, err := tpm2.KDFa(aik.Alg, seed, labelIntegrity, nil, nil, hashNew().Size()*8)
	if err != nil {
		return nil, nil, fmt.Errorf("generating HMAC key: %v", err)
	}

	mac := hmac.New(hashNew, macKey)
	mac.Write(encIdentity)
	mac.Write(aikNameEncoded)
	integrityHMAC := mac.Sum(nil)

	idObject := &tpm2.IDObject{
		IntegrityHMAC: integrityHMAC,
		EncIdentity:   encIdentity,
	}
	id, err := idObject.Encode()
	if err != nil {
		return nil, nil, fmt.Errorf("encoding IDObject: %v", err)
	}
	packedEncSecret, err := tpmutil.Pack(encSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("packing encSecret: %v", err)
	}

	return id, packedEncSecret, nil
}

func ClientActivate(rw io.ReadWriter, activeHandle, keyHandle tpmutil.Handle, credBlob, encSecret []byte) ([]byte, error) {
	// TODO(joerichey): Add some error checking (maybe pass in keys (instead of handles))

	// Step a: Setup Policy Authorization Session
	session, _, err := tpm2.StartAuthSession(
		rw,
		tpm2.HandleNull,  /*tpmKey*/
		tpm2.HandleNull,  /*bindKey*/
		make([]byte, 16), /*nonceCaller*/
		nil,              /*secret*/
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		return nil, fmt.Errorf("StartAuthSession: %v", err)
	}
	defer tpm2.FlushContext(rw, session)

	// Step b: Configure EK hierarchy to use the session
	if err := tpm2.PolicySecret(rw, tpm2.HandleEndorsement, "", session, nil, nil, nil); err != nil {
		return nil, fmt.Errorf("PolicySecret: %v", err)
	}

	// Step c: Run ActivateCredential, authenticating using the session
	auth := []tpm2.AuthCommand{
		tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession, Auth: nil},
		tpm2.AuthCommand{Session: session, Attributes: tpm2.AttrContinueSession, Auth: nil},
	}
	return tpm2.ActivateCredentialUsingAuth(rw, auth, activeHandle, keyHandle, credBlob, encSecret)
}
