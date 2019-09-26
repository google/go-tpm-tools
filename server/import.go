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
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"github.com/google/go-tpm-tools/proto"
)

// CreateImportBlob uses the provided public EK to encrypt the sensitive data into import blob format.
// The returned import blob can be decrypted by the TPM associated with the provided EK.
func CreateImportBlob(ekPub crypto.PublicKey, sensitive []byte) (*proto.ImportBlob, error) {
	ek, err := CreateEKPublicAreaFromKey(ekPub)
	if err != nil {
		return nil, err
	}
	private := createPrivate(sensitive, ek.NameAlg)
	public := createPublic(private, ek.NameAlg)
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
	return &proto.ImportBlob{
		Duplicate:     duplicate,
		EncryptedSeed: encryptedSeed,
		PublicArea:    pubEncoded,
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

func createPublic(private tpm2.Private, hashAlg tpm2.Algorithm) tpm2.Public {
	publicHash := getHash(hashAlg)
	publicHash.Write(private.SeedValue)
	publicHash.Write(private.Sensitive)
	return tpm2.Public{
		Type:       tpm2.AlgKeyedHash,
		NameAlg:    hashAlg,
		Attributes: tpm2.FlagUserWithAuth,
		KeyedHashParameters: &tpm2.KeyedHashParams{
			Alg:    tpm2.AlgNull,
			Unique: publicHash.Sum(nil),
		},
	}
}

func createRSASeed(ek tpm2.Public) (seed, encryptedSeed []byte, err error) {
	seedSize := ek.RSAParameters.Symmetric.KeyBits / 8
	seed = make([]byte, seedSize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		panic(err)
	}

	ekPub, err := ek.Key()
	if err != nil {
		return
	}
	encryptedSeed, err = rsa.EncryptOAEP(
		getHash(ek.NameAlg),
		rand.Reader,
		ekPub.(*rsa.PublicKey),
		seed,
		[]byte("DUPLICATE\x00"))
	if err != nil {
		return
	}
	encryptedSeed, err = tpmutil.Pack(encryptedSeed)
	return
}

func createECCSeed(ek tpm2.Public) (seed, encryptedSeed []byte, err error) {
	var curve elliptic.Curve
	switch ek.ECCParameters.CurveID {
	case tpm2.CurveNISTP224:
		curve = elliptic.P224()
	case tpm2.CurveNISTP256:
		curve = elliptic.P256()
	case tpm2.CurveNISTP384:
		curve = elliptic.P384()
	case tpm2.CurveNISTP521:
		curve = elliptic.P521()
	default:
		return nil, nil, fmt.Errorf("unsupported elliptic curve: %v", ek.ECCParameters.CurveID)
	}
	priv, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return
	}
	ekPoint := ek.ECCParameters.Point
	z, _ := curve.ScalarMult(ekPoint.X(), ekPoint.Y(), priv)
	xBytes := eccIntToBytes(x, curve)

	seed, err = tpm2.KDFe(
		ek.NameAlg,
		eccIntToBytes(z, curve),
		"DUPLICATE",
		xBytes,
		eccIntToBytes(ekPoint.X(), curve),
		getHash(ek.NameAlg).Size()*8)
	if err != nil {
		return
	}
	encryptedSeed, err = tpmutil.Pack(tpmutil.U16Bytes(xBytes), tpmutil.U16Bytes(eccIntToBytes(y, curve)))
	return
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
	iv := make([]byte, 16)
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
	create, err := hashAlg.HashConstructor()
	if err != nil {
		panic(err)
	}
	return create()
}

// ECC coordinates need to maintain a specific size based on the curve, so we pad the front with zeros.
func eccIntToBytes(key *big.Int, curve elliptic.Curve) []byte {
	bytes := key.Bytes()
	return append(make([]byte, (curve.Params().BitSize+7)/8-len(bytes)), bytes...)
}
