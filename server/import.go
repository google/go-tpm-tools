package server

import (
	"crypto"
	"fmt"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"hash"
	"io"

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
	if ek.Type == tpm2.AlgRSA {
		seed = createRandomSeed(ek)
		encryptedSeed, err = encryptSeed(seed, ek)
		if err != nil {
			return nil, err
		}
	} else if ek.Type == tpm2.AlgECC {
		curve := elliptic.P256() // TODO Get from ek.
		priv, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, err
		}
		ekPoint := ek.ECCParameters.Point
		z, _ := curve.ScalarMult(ekPoint.X(), ekPoint.Y(), priv)

		seed, err = tpm2.KDFe(
			ek.NameAlg,
			z.Bytes(),
			"DUPLICATE",
			x.Bytes(),
			ekPoint.X().Bytes(),
			256)
//			int(ek.ECCParameters.Symmetric.KeyBits))
		if err != nil {
			return nil, err
		}
		encryptedSeed, err = tpmutil.Pack(tpmutil.U16Bytes(x.Bytes()), tpmutil.U16Bytes(y.Bytes()))
		if err != nil {
			return nil, fmt.Errorf("err: %v", err)
		}
		if len(encryptedSeed) != 128 {
	//		encryptedSeed = append(make([]byte, 128-len(encryptedSeed)), encryptedSeed...)
	//		encryptedSeed = append(encryptedSeed, make([]byte, 128-len(encryptedSeed))...)
		//	return nil, fmt.Errorf("size %v", len(encryptedSeed))
		}
	}
	duplicate, err := createDuplicate(private, seed, public, ek.NameAlg)
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

func createRandomSeed(ek tpm2.Public) []byte {
	seedSize := ek.RSAParameters.Symmetric.KeyBits / 8
	seed := make([]byte, seedSize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		panic(err)
	}
	return seed
}

func encryptSeed(seed []byte, ek tpm2.Public) ([]byte, error) {
	ekPub, err := ek.Key()
	if err != nil {
		return nil, err
	}
	encSeed, err := rsa.EncryptOAEP(
		getHash(ek.NameAlg),
		rand.Reader,
		ekPub.(*rsa.PublicKey),
		seed,
		[]byte("DUPLICATE\x00"))
	if err != nil {
		return nil, err
	}

	return tpmutil.Pack(encSeed)
}

func createDuplicate(private tpm2.Private, seed []byte, public tpm2.Public, hashAlg tpm2.Algorithm) ([]byte, error) {
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
	encryptedSecret, err := encryptSecret(packedSecret, seed, nameEncoded, hashAlg)
	if err != nil {
		return nil, err
	}
	macSum, err := createHMAC(encryptedSecret, nameEncoded, seed, hashAlg)
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

func encryptSecret(secret, seed, nameEncoded []byte, hashAlg tpm2.Algorithm) ([]byte, error) {
	symmetricKey, err := tpm2.KDFa(
		hashAlg,
		seed,
		"STORAGE",
		nameEncoded,
		/*contextV=*/ nil,
		len(seed)*8)
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
