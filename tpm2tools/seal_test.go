package tpm2tools

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"github.com/google/go-tpm-tools/internal"
)

func TestSeal(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer CheckedClose(t, rwc)

	type SRKey struct {
		name string
		key *Key
	}
	keys := []SRKey{};

	key, err := StorageRootKeyECC(rwc)
	if err != nil {
		t.Fatalf("can't create ECC srk from template: %v", err)
	}
	keys = append(keys, SRKey{name: "ECC", key: key})
	key, err = StorageRootKeyRSA(rwc)
	if err != nil {
		t.Fatalf("can't create RSA srk from template: %v", err)
	}
	keys = append(keys, SRKey{name: "RSA", key: key})
	
	defer func() {
		for _, k := range keys {
			k.key.Close()
		}
	} ()

	for _, k := range keys {
		t.Run(k.name, func(t *testing.T) {
			secret := []byte("test")
			pcrList := []int{7, 23}
			pcrToExtend := tpmutil.Handle(23)
		
			sealed, err := k.key.Seal(pcrList, secret)
			if err != nil {
				t.Fatalf("failed to seal: %v", err)
			}
		
			unseal, err := k.key.Unseal(sealed)
			if err != nil {
				t.Fatalf("failed to unseal: %v", err)
			}
			if !bytes.Equal(secret, unseal) {
				t.Fatalf("unsealed (%v) not equal to secret (%v)", unseal, secret)
			}
		
			extension := bytes.Repeat([]byte{0xAA}, sha256.Size)
			err = tpm2.PCRExtend(rwc, pcrToExtend, tpm2.AlgSHA256, extension, "")
			if err != nil {
				t.Fatalf("failed to extend pcr: %v", err)
			}
		
			// unseal should not succeed.
			_, err = k.key.Unseal(sealed)
			if err == nil {
				t.Fatalf("unseal should have caused an error: %v", err)
			}
		})
	}
}

func TestComputeSessionAuth(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer CheckedClose(t, rwc)

	pcrList := []int{1, 7}

	pcrs := map[int][]byte{}

	for _, pcrNum := range pcrList {
		pcrVal, err := tpm2.ReadPCR(rwc, pcrNum, tpm2.AlgSHA256)
		if err != nil {
			t.Fatalf("failed to read pcr: %v", err)
		}

		pcrs[pcrNum] = pcrVal
	}

	getAuth, err := getPCRSessionAuth(rwc, pcrList)
	if err != nil {
		t.Fatalf("failed to get session auth: %v", err)
	}

	computeAuth, err := computePCRSessionAuth(pcrs)
	if err != nil {
		t.Fatalf("failed to compute session auth: %v", err)
	}

	if !bytes.Equal(computeAuth, getAuth) {
		t.Fatalf("computed auth (%v) not equal to session auth(%v)", computeAuth, getAuth)
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
	pcrs := map[int][]byte{}
	for _, pcrNum := range pcrList {
		pcrVal, err := tpm2.ReadPCR(rwc, pcrNum, tpm2.AlgSHA256)
		if err != nil {
			t.Fatalf("failed to read pcr: %v", err)
		}

		pcrs[pcrNum] = pcrVal
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

	sealed, err = key.Reseal(pcrs, sealed)
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
	pcrs := map[int][]byte{}
	for _, pcrNum := range pcrList {
		pcrVal, err := tpm2.ReadPCR(rwc, pcrNum, tpm2.AlgSHA256)
		if err != nil {
			t.Fatalf("failed to read pcr: %v", err)
		}

		pcrs[pcrNum] = pcrVal
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
	pcrs[pcrToChange] = computePCRValue(pcrs[pcrToChange], extensions)
	sealed, err = key.Reseal(pcrs, sealed)
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
