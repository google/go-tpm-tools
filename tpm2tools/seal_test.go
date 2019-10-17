package tpm2tools

import (
	"bytes"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"github.com/google/go-tpm-tools/internal"
	"github.com/google/go-tpm-tools/proto"
)

func TestSeal(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer CheckedClose(t, rwc)

	tests := []struct {
		name   string
		getSRK func(io.ReadWriter) (*Key, error)
	}{
		{"RSA", StorageRootKeyRSA},
		{"ECC", StorageRootKeyECC},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			srk, err := test.getSRK(rwc)
			if err != nil {
				t.Fatalf("can't create %s srk from template: %v", test.name, err)
			}
			defer srk.Close()

			secret := []byte("test")
			pcrList := []int{7, 23}
			pcrToExtend := tpmutil.Handle(23)

			sealed, err := srk.Seal(pcrList, secret)
			if err != nil {
				t.Fatalf("failed to seal: %v", err)
			}

			unseal, err := srk.Unseal(sealed)
			if err != nil {
				t.Fatalf("failed to unseal: %v", err)
			}
			if !bytes.Equal(secret, unseal) {
				t.Fatalf("unsealed (%v) not equal to secret (%v)", unseal, secret)
			}

			extension := bytes.Repeat([]byte{0xAA}, sha256.Size)
			if err = tpm2.PCRExtend(rwc, pcrToExtend, tpm2.AlgSHA256, extension, ""); err != nil {
				t.Fatalf("failed to extend pcr: %v", err)
			}

			// unseal should not succeed.
			if _, err = srk.Unseal(sealed); err == nil {
				t.Fatalf("unseal should have caused an error: %v", err)
			}
		})
	}
}

func TestComputeSessionAuth(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer CheckedClose(t, rwc)

	pcrList := []int{1, 7}
	pcrs := map[uint32][]byte{}

	tests := []struct {
		name     string
		alg      tpm2.Algorithm
		protoAlg proto.HashAlgo
	}{
		{"sha1", tpm2.AlgSHA1, proto.HashAlgo_SHA1},
		{"sha256", tpm2.AlgSHA256, proto.HashAlgo_SHA256},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			for _, pcrNum := range pcrList {
				pcrVal, err := tpm2.ReadPCR(rwc, pcrNum, test.alg)
				if err != nil {
					t.Fatalf("failed to read pcr: %v", err)
				}

				pcrs[uint32(pcrNum)] = pcrVal
			}

			getAuth, err := getPCRSessionAuth(rwc, pcrList, test.alg)
			if err != nil {
				t.Fatalf("failed to get session auth: %v", err)
			}

			computeAuth, err := ComputePCRSessionAuth(proto.Pcrs{Hash: test.protoAlg, Pcrs: pcrs})
			if err != nil {
				t.Fatalf("failed to compute session auth: %v", err)
			}

			if !bytes.Equal(computeAuth, getAuth) {
				t.Fatalf("computed auth (%v) not equal to session auth(%v)", computeAuth, getAuth)
			}
		})
	}
}

func TestSelfReseal(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer CheckedClose(t, rwc)

	key, err := StorageRootKeyRSA(rwc)
	if err != nil {
		t.Fatalf("can't create srk from template: %v", err)
	}
	defer key.Close()

	secret := []byte("test")

	pcrList := []int{0, 4, 7}
	pcrs := map[uint32][]byte{}
	for _, pcrNum := range pcrList {
		pcrVal, err := tpm2.ReadPCR(rwc, pcrNum, tpm2.AlgSHA256)
		if err != nil {
			t.Fatalf("failed to read pcr: %v", err)
		}

		pcrs[uint32(pcrNum)] = pcrVal
	}

	sealed, err := key.Seal(pcrList, secret)
	if err != nil {
		t.Fatalf("failed to seal: %v", err)
	}

	unseal, err := key.Unseal(sealed)
	if err != nil {
		t.Fatalf("failed to unseal: %v", err)
	}
	if !bytes.Equal(secret, unseal) {
		t.Fatalf("unsealed (%v) not equal to secret (%v)", unseal, secret)
	}

	sealed, err = key.Reseal(proto.Pcrs{Hash: proto.HashAlgo_SHA256, Pcrs: pcrs}, sealed)
	if err != nil {
		t.Fatalf("failed to reseal: %v", err)
	}

	unseal, err = key.Unseal(sealed)
	if err != nil {
		t.Fatalf("unseal failed: %v", err)
	}
	if !bytes.Equal(secret, unseal) {
		t.Fatalf("unsealed (%v) not equal to secret (%v)", unseal, secret)
	}
}

func computePCRValue(base []byte, extensions [][]byte) []byte {
	for _, extension := range extensions {
		sum := sha256.Sum256(append(base, extension...))
		base = sum[:]
	}
	return base
}

func TestComputePCRValue(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer CheckedClose(t, rwc)

	pcrNum := 23
	extensions := [][]byte{
		bytes.Repeat([]byte{0xAA}, sha256.Size),
		bytes.Repeat([]byte{0xAB}, sha256.Size),
		bytes.Repeat([]byte{0xAC}, sha256.Size),
		bytes.Repeat([]byte{0xAD}, sha256.Size),
	}

	pcrBase, err := tpm2.ReadPCR(rwc, pcrNum, tpm2.AlgSHA256)
	if err != nil {
		t.Fatalf("failed to read pcr %v", err)
	}

	for _, extension := range extensions {
		err := tpm2.PCRExtend(rwc, tpmutil.Handle(pcrNum), tpm2.AlgSHA256, extension, "")
		if err != nil {
			t.Fatalf("failed to extend pcr: %v", err)
		}
	}

	pcrVal, err := tpm2.ReadPCR(rwc, pcrNum, tpm2.AlgSHA256)
	if err != nil {
		t.Fatalf("failed to read pcr %v", err)
	}

	computedValue := computePCRValue(pcrBase, extensions)
	if !bytes.Equal(pcrVal, computedValue) {
		t.Fatalf("pcrVal (%v) not equal to computedValue (%v)", pcrVal, computedValue)
	}
}

func TestReseal(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer CheckedClose(t, rwc)

	key, err := StorageRootKeyRSA(rwc)
	if err != nil {
		t.Fatalf("can't create srk from template: %v", err)
	}
	defer key.Close()

	secret := []byte("test")

	pcrToChange := 23
	pcrList := []int{7, 23}
	pcrs := map[uint32][]byte{}
	for _, pcrNum := range pcrList {
		pcrVal, err := tpm2.ReadPCR(rwc, pcrNum, tpm2.AlgSHA256)
		if err != nil {
			t.Fatalf("failed to read pcr: %v", err)
		}

		pcrs[uint32(pcrNum)] = pcrVal
	}

	sealed, err := key.Seal(pcrList, secret)
	if err != nil {
		t.Fatalf("failed to seal: %v", err)
	}

	unseal, err := key.Unseal(sealed)
	if err != nil {
		t.Fatalf("failed to unseal: %v", err)
	}
	if !bytes.Equal(secret, unseal) {
		t.Fatalf("unsealed (%v) not equal to secret (%v)", unseal, secret)
	}

	extensions := [][]byte{
		bytes.Repeat([]byte{0xAA}, sha256.Size),
	}

	// Change pcr value to the predicted future value for resealing
	pcrs[uint32(pcrToChange)] = computePCRValue(pcrs[uint32(pcrToChange)], extensions)
	sealed, err = key.Reseal(proto.Pcrs{Hash: proto.HashAlgo_SHA256, Pcrs: pcrs}, sealed)
	if err != nil {
		t.Fatalf("failed to reseal: %v", err)
	}

	// unseal should not succeed since pcr has not been extended.
	_, err = key.Unseal(sealed)
	if err == nil {
		t.Fatalf("unseal should have failed: %v", err)
	}

	for _, extension := range extensions {
		err = tpm2.PCRExtend(rwc, tpmutil.Handle(pcrToChange), tpm2.AlgSHA256, extension, "")
		if err != nil {
			t.Fatalf("failed to extend pcr: %v", err)
		}
	}

	unseal, err = key.Unseal(sealed)
	if err != nil {
		t.Fatalf("failed to unseal: %v", err)
	}
	if !bytes.Equal(secret, unseal) {
		t.Fatalf("unsealed (%v) not equal to secret (%v)", unseal, secret)
	}
}
