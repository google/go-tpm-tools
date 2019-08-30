package server

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"hash"
	"io"

	pb "github.com/google/go-tpm-tools/proto"
)

// hashConstants contains all the per-EK constant hash values in a convenient struct.
type hashConstants struct {
	alg    tpm2.Algorithm
	create (func() hash.Hash)
	size   int
}

// CreateImportBlob uses the provided public EK to encrypt the sensitive data into import blob format.
// The returned import blob can be decrypted by the TPM associated with the provided EK.
func CreateImportBlob(ekPub crypto.PublicKey, sensitive []byte) (*pb.ImportBlob, error) {
	ek, err := tpm2tools.CreatePublicAreaFromPublicKey(ekPub)
	if err != nil {
		return nil, err
	}
	hashConsts, err := initializeHashConstants(ek)
	if err != nil {
		return nil, err
	}
	private := createPrivate(sensitive, hashConsts.size)
	public := createPublic(private, hashConsts)
	pubEncoded, err := public.Encode()
	if err != nil {
		return nil, err
	}
	seed := createRandomSeed(ek)
	encryptedSeed, err := encryptSeed(seed, ek, hashConsts.create())
	if err != nil {
		return nil, err
	}
	duplicate, err := createDuplicate(private, seed, public, hashConsts)
	if err != nil {
		return nil, err
	}
	return &pb.ImportBlob{
			Duplicate:     duplicate,
			EncryptedSeed: encryptedSeed,
			PublicArea:    pubEncoded,
	}, nil
}

func createDuplicate(private tpm2.Private, seed []byte, public tpm2.Public, hashConsts hashConstants) ([]byte, error) {
	nameEncoded, err := getEncodedName(public)
	if err != nil {
		return nil, err
	}
	secret, err := encodePrivate(private)
	if err != nil {
		return nil, err
	}
	encryptedSecret, err := encryptSecret(secret, seed, nameEncoded, hashConsts.alg)
	if err != nil {
		return nil, err
	}
	macSum, err := createHMAC(encryptedSecret, nameEncoded, seed, hashConsts)
	if err != nil {
		return nil, err
	}
	return tpmutil.Pack(tpm2.IDObject{
		IntegrityHMAC: macSum,
		EncIdentity:   encryptedSecret,
	})
}

func createHMAC(encryptedSecret, nameEncoded, seed []byte, hashConsts hashConstants) ([]byte, error) {
	macKey, err := tpm2.KDFa(hashConsts.alg, seed, "INTEGRITY", /*contextU=*/nil, /*contextV=*/nil, hashConsts.size*8)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(hashConsts.create, macKey)
	mac.Write(encryptedSecret)
	mac.Write(nameEncoded)

	return mac.Sum(nil), nil
}

func getEncodedName(public tpm2.Public) ([]byte, error) {
	name, err := public.Name()
	if err != nil {
		return nil, err
	}
	nameEncoded, err := name.Digest.Encode()
	if err != nil {
		return nil, err
	}
	return nameEncoded, nil
}

func encodePrivate(private tpm2.Private) ([]byte, error) {
	secret, err := private.Encode()
	if err != nil {
		return nil, err
	}
	packedSecret, err := tpmutil.Pack(tpmutil.U16Bytes(secret))
	if err != nil {
		return nil, err
	}
	return packedSecret, nil
}

func encryptSecret(secret, seed, nameEncoded []byte, hashAlg tpm2.Algorithm) ([]byte, error) {
	symmetricKey, err := tpm2.KDFa(hashAlg, seed, "STORAGE", nameEncoded, /*contextV=*/nil, len(seed)*8)
	if err != nil {
		return nil, err
	}
	c, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, err
	}
	encSecret := make([]byte, len(secret))
	iv := make([]byte, len(symmetricKey))
	cipher.NewCFBEncrypter(c, iv).XORKeyStream(encSecret, secret)
	return encSecret, nil
}

func encryptSeed(seed []byte, ek tpm2.Public, h hash.Hash) ([]byte, error) {
	label := append([]byte("DUPLICATE"), 0)
	ekPub, err := ek.Key()
	if err != nil {
		return nil, err
	}
	encSeed, err := rsa.EncryptOAEP(h, rand.Reader, ekPub.(*rsa.PublicKey), seed, label)
	if err != nil {
		return nil, err
	}

	packedSeed, err := tpmutil.Pack(encSeed)
	if err != nil {
		return nil, err
	}
	return packedSeed, nil
}

func createRandomSeed(ek tpm2.Public) []byte {
	symBlockSize := ek.RSAParameters.Symmetric.KeyBits / 8
	seed := make([]byte, symBlockSize)
	io.ReadFull(rand.Reader, seed)
	return seed
}

func createPublic(private tpm2.Private, hashConsts hashConstants) tpm2.Public {
	publicHash := hashConsts.create()
	publicHash.Write(private.SeedValue)
	publicHash.Write(private.Sensitive)
	return tpm2.Public{
		Type:       tpm2.AlgKeyedHash,
		NameAlg:    hashConsts.alg,
		Attributes: tpm2.FlagUserWithAuth,
		KeyedHashParameters: &tpm2.KeyedHashParams{
			Alg:    tpm2.AlgNull,
			Unique: publicHash.Sum(nil),
		},
	}
}

func createPrivate(sensitive []byte, hashSize int) tpm2.Private {
	private := tpm2.Private{
		Type:      tpm2.AlgKeyedHash,
		AuthValue: nil,
		SeedValue: make([]byte, hashSize),
		Sensitive: sensitive,
	}
	io.ReadFull(rand.Reader, private.SeedValue)
	return private
}

func initializeHashConstants(ek tpm2.Public) (hashConstants, error) {
	alg := ek.NameAlg
	create, err := alg.HashConstructor()
	if err != nil {
		return hashConstants{}, err
	}
	temp := create()
	return hashConstants{alg, create, temp.Size()}, nil
}
