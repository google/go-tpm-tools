// Package server contains functions to be ran on a server (no TPM needed), as oppose to a client (with TPM).
package server

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"hash"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"

	tpmpb "github.com/google/go-tpm-tools/proto"
	"github.com/google/go-tpm-tools/tpm2tools"
)

// CreateImportBlob uses the provided public EK to encrypt the sensitive data into import blob format.
// The returned import blob can be decrypted by the TPM associated with the provided EK.
// The pcrs parameter is used to create a PCR policy on the object to be imported using the SHA256 versions of the provided PCRs. A nil pcrs value will allow password/HMAC authorization.
func CreateImportBlob(ekPub crypto.PublicKey, sensitive []byte, pcrs map[int][]byte) (*tpmpb.ImportBlob, error) {
	ek, err := CreateEKPublicAreaFromKey(ekPub)
	if err != nil {
		return nil, err
	}
	private := createPrivate(sensitive, ek.NameAlg)
	public, err := createPublic(private, ek.NameAlg, pcrs)
	if err != nil {
		return nil, err
	}
	var seed, encryptedSeed []byte
	switch ek.Type {
	case tpm2.AlgRSA:
		seed, encryptedSeed, err = createRSASeed(ek)
		if err != nil {
			return nil, err
		}
	case tpm2.AlgECC:
		seed, encryptedSeed, err = createECCSeed(ek)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported EK type: %v", ek.Type)
	}
	duplicate, err := createDuplicate(private, seed, public, ek)
	if err != nil {
		return nil, err
	}
	pubEncoded, err := public.Encode()
	if err != nil {
		return nil, err
	}
	// Create list of PCRs used in the PCR policy.
	var pcrList []int32
	for pcr := range pcrs {
		pcrList = append(pcrList, int32(pcr))
	}

	return &tpmpb.ImportBlob{
		Duplicate:     duplicate,
		EncryptedSeed: encryptedSeed,
		PublicArea:    pubEncoded,
		Pcrs:          pcrList,
	}, nil
}

func createPrivate(sensitive []byte, hashAlg tpm2.Algorithm) tpm2.Private {
	private := tpm2.Private{
		Type:      tpm2.AlgKeyedHash,
		AuthValue: nil,
		SeedValue: make([]byte, getHash(hashAlg).Size()),
		Sensitive: sensitive,
	}
	if _, err := io.ReadFull(rand.Reader, private.SeedValue); err != nil {
		panic(err)
	}
	return private
}

func createPublic(private tpm2.Private, hashAlg tpm2.Algorithm, pcrs map[int][]byte) (tpm2.Public, error) {
	var attr tpm2.KeyProp
	var auth []byte
	var err error
	if len(pcrs) > 0 {
		auth, err = tpm2tools.ComputePCRSessionAuth(pcrs)
		if err != nil {
			return tpm2.Public{}, err
		}
	} else {
		// If we aren't using a PCR policy, allow password/HMAC authorization.
		attr = tpm2.FlagUserWithAuth
	}
	publicHash := getHash(hashAlg)
	publicHash.Write(private.SeedValue)
	publicHash.Write(private.Sensitive)
	return tpm2.Public{
		Type:       tpm2.AlgKeyedHash,
		NameAlg:    hashAlg,
		AuthPolicy: auth,
		Attributes: attr,
		KeyedHashParameters: &tpm2.KeyedHashParams{
			Alg:    tpm2.AlgNull,
			Unique: publicHash.Sum(nil),
		},
	}, nil
}

func createRSASeed(ek tpm2.Public) (seed, encryptedSeed []byte, err error) {
	seedSize := ek.RSAParameters.Symmetric.KeyBits / 8
	seed = make([]byte, seedSize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		panic(err)
	}

	ekPub, err := ek.Key()
	if err != nil {
		return nil, nil, err
	}
	encryptedSeed, err = rsa.EncryptOAEP(
		getHash(ek.NameAlg),
		rand.Reader,
		ekPub.(*rsa.PublicKey),
		seed,
		[]byte("DUPLICATE\x00"))
	if err != nil {
		return nil, nil, err
	}
	encryptedSeed, err = tpmutil.Pack(encryptedSeed)
	return seed, encryptedSeed, err
}

func createECCSeed(ek tpm2.Public) (seed, encryptedSeed []byte, err error) {
	curve, err := curveIDToGoCurve(ek.ECCParameters.CurveID)
	if err != nil {
		return nil, nil, err
	}
	priv, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ekPoint := ek.ECCParameters.Point
	z, _ := curve.ScalarMult(ekPoint.X(), ekPoint.Y(), priv)
	xBytes := eccIntToBytes(curve, x)

	seed, err = tpm2.KDFe(
		ek.NameAlg,
		eccIntToBytes(curve, z),
		"DUPLICATE",
		xBytes,
		eccIntToBytes(curve, ekPoint.X()),
		getHash(ek.NameAlg).Size()*8)
	if err != nil {
		return nil, nil, err
	}
	encryptedSeed, err = tpmutil.Pack(tpmutil.U16Bytes(xBytes), tpmutil.U16Bytes(eccIntToBytes(curve, y)))
	return seed, encryptedSeed, err
}

func createDuplicate(private tpm2.Private, seed []byte, public, ek tpm2.Public) ([]byte, error) {
	nameEncoded, err := getEncodedName(public)
	if err != nil {
		return nil, err
	}
	secret, err := private.Encode()
	if err != nil {
		return nil, err
	}
	packedSecret, err := tpmutil.Pack(tpmutil.U16Bytes(secret))
	if err != nil {
		return nil, err
	}
	encryptedSecret, err := encryptSecret(packedSecret, seed, nameEncoded, ek)
	if err != nil {
		return nil, err
	}
	macSum, err := createHMAC(encryptedSecret, nameEncoded, seed, ek.NameAlg)
	if err != nil {
		return nil, err
	}
	return tpmutil.Pack(tpm2.IDObject{
		IntegrityHMAC: macSum,
		EncIdentity:   encryptedSecret,
	})
}

func getEncodedName(public tpm2.Public) ([]byte, error) {
	name, err := public.Name()
	if err != nil {
		return nil, err
	}
	return name.Digest.Encode()
}

func encryptSecret(secret, seed, nameEncoded []byte, ek tpm2.Public) ([]byte, error) {
	var symSize int
	switch ek.Type {
	case tpm2.AlgRSA:
		symSize = int(ek.RSAParameters.Symmetric.KeyBits)
	case tpm2.AlgECC:
		symSize = int(ek.ECCParameters.Symmetric.KeyBits)
	default:
		return nil, fmt.Errorf("unsupported EK type: %v", ek.Type)
	}

	symmetricKey, err := tpm2.KDFa(
		ek.NameAlg,
		seed,
		"STORAGE",
		nameEncoded,
		/*contextV=*/ nil,
		symSize)
	if err != nil {
		return nil, err
	}
	c, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, err
	}
	encSecret := make([]byte, len(secret))
	// The TPM spec requires an all-zero IV.
	iv := make([]byte, len(symmetricKey))
	cipher.NewCFBEncrypter(c, iv).XORKeyStream(encSecret, secret)
	return encSecret, nil
}

func createHMAC(encryptedSecret, nameEncoded, seed []byte, hashAlg tpm2.Algorithm) ([]byte, error) {
	macKey, err := tpm2.KDFa(
		hashAlg,
		seed,
		"INTEGRITY",
		/*contextU=*/ nil,
		/*contextV=*/ nil,
		getHash(hashAlg).Size()*8)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(func() hash.Hash { return getHash(hashAlg) }, macKey)
	mac.Write(encryptedSecret)
	mac.Write(nameEncoded)

	return mac.Sum(nil), nil
}

func getHash(hashAlg tpm2.Algorithm) hash.Hash {
	create, err := hashAlg.Hash()
	if err != nil {
		panic(err)
	}
	return create.New()
