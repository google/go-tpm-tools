package tpm2tools

import (
	"bytes"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"github.com/google/go-tpm-tools/internal"
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
			sealingConfig := CurrentPCRs{
				PCRSel: tpm2.PCRSelection{
					Hash: tpm2.AlgSHA256,
					PCRs: []int{7, 23},
				},
				RW: rwc,
			}

			sealed, err := srk.Seal(secret, sealingConfig, tpm2.PCRSelection{})
			if err != nil {
				t.Fatalf("failed to seal: %v", err)
			}

			unseal, err := srk.Unseal(sealed, nil)
			if err != nil {
				t.Fatalf("failed to unseal: %v", err)
			}
			if !bytes.Equal(secret, unseal) {
				t.Fatalf("unsealed (%v) not equal to secret (%v)", unseal, secret)
			}

			extension := bytes.Repeat([]byte{0xAA}, sha256.Size)
			if err = tpm2.PCRExtend(rwc, tpmutil.Handle(23), tpm2.AlgSHA256, extension, ""); err != nil {
				t.Fatalf("failed to extend pcr: %v", err)
			}

			// unseal should not succeed.
			if _, err = srk.Unseal(sealed, nil); err == nil {
				t.Fatalf("unseal should have caused an error: %v", err)
			}
		})
	}
}

func TestSealWithCertify(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer CheckedClose(t, rwc)

	key, err := StorageRootKeyRSA(rwc)
	if err != nil {
		t.Fatalf("can't create srk from template: %v", err)
	}
	defer key.Close()

	secret := []byte("test")
	sealingConfig := CurrentPCRs{
		PCRSel: tpm2.PCRSelection{
			Hash: tpm2.AlgSHA256,
			PCRs: []int{4, 7}},
		RW: rwc,
	}
	pcrListCert := []int{1}
	certifyConfig := CurrentPCRs{
		PCRSel: tpm2.PCRSelection{
			Hash: tpm2.AlgSHA256,
			PCRs: pcrListCert},
		RW: rwc,
	}

	sealed, err := key.Seal(secret, sealingConfig, tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrListCert})
	unseal, err := key.Unseal(sealed, certifyConfig)
	if err != nil {
		t.Fatalf("unseal should success %v", err)
	}
	if !bytes.Equal(unseal, secret) {
		t.Fatalf("unsealed (%v) not equal to secret (%v)", unseal, secret)
	}

	// extend a PCR value used for certification
	extension := bytes.Repeat([]byte{0xAA}, sha256.Size)
	tpm2.PCRExtend(rwc, tpmutil.Handle(1), tpm2.AlgSHA256, extension, "")

	unseal, err = key.Unseal(sealed, nil)
	if err != nil {
		t.Fatalf("unseal should success without certification %v", err)
	}
	if !bytes.Equal(unseal, secret) {
		t.Fatalf("unsealed (%v) not equal to secret (%v)", unseal, secret)
	}
	unseal, err = key.Unseal(sealed, certifyConfig)
	if err == nil {
		t.Fatalf("unseal should fail with certification of current PCRs")
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
	sealingConfig := CurrentPCRs{
		PCRSel: tpm2.PCRSelection{
			Hash: tpm2.AlgSHA256,
			PCRs: pcrList,
		},
		RW: rwc,
	}

	resealTargetPCRs, err := ReadPCRs(rwc, pcrList, tpm2.AlgSHA256)
	if err != nil {
		t.Fatalf("failed to readPCR: %v", err)
	}

	sealed, err := key.Seal(secret, sealingConfig, tpm2.PCRSelection{})
	if err != nil {
		t.Fatalf("failed to seal: %v", err)
	}

	unseal, err := key.Unseal(sealed, nil)
	if err != nil {
		t.Fatalf("failed to unseal: %v", err)
	}
	if !bytes.Equal(secret, unseal) {
		t.Fatalf("unsealed (%v) not equal to secret (%v)", unseal, secret)
	}

	sealed, err = key.Reseal(sealed, nil, TargetPCRs{resealTargetPCRs}, tpm2.PCRSelection{})
	if err != nil {
		t.Fatalf("failed to reseal: %v", err)
	}

	unseal, err = key.Unseal(sealed, nil)
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
	sealingConfig := CurrentPCRs{
		PCRSel: tpm2.PCRSelection{
			Hash: tpm2.AlgSHA256,
			PCRs: pcrList,
		},
		RW: rwc,
	}

	pcrsInitial, err := ReadPCRs(rwc, pcrList, tpm2.AlgSHA256)
	pcrsBeingModified, err := ReadPCRs(rwc, pcrList, tpm2.AlgSHA256)

	sealed, err := key.Seal(secret, sealingConfig, tpm2.PCRSelection{})
	if err != nil {
		t.Fatalf("failed to seal: %v", err)
	}

	unseal, err := key.Unseal(sealed, nil)
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
	pcrsBeingModified.GetPcrs()[uint32(pcrToChange)] = computePCRValue(pcrsBeingModified.GetPcrs()[uint32(pcrToChange)], extensions)

	sealed, err = key.Reseal(sealed, nil, TargetPCRs{pcrsBeingModified}, tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrList})
	if err != nil {
		t.Fatalf("failed to reseal: %v", err)
	}

	// unseal should not succeed since pcr has not been extended.
	_, err = key.Unseal(sealed, nil)
	if err == nil {
		t.Fatalf("unseal should have failed: %v", err)
	}

	for _, extension := range extensions {
		err = tpm2.PCRExtend(rwc, tpmutil.Handle(pcrToChange), tpm2.AlgSHA256, extension, "")
		if err != nil {
			t.Fatalf("failed to extend pcr: %v", err)
		}
	}

	// unseal should not success if certify to current PCRs value, as one PCR has changed
	unseal, err = key.Unseal(sealed, CurrentPCRs{PCRSel: tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrList}, RW: rwc})
	if err == nil {
		t.Fatalf("unseal should fail since the certify PCRs have changed.")
	}

	// ceritfy to original PCRs value (PCRs value when do the sealing) will work
	unseal, err = key.Unseal(sealed, ExpectedPCRs{pcrsInitial})
	if err != nil {
		t.Fatalf("failed to unseal: %v", err)
	}
	if !bytes.Equal(secret, unseal) {
		t.Fatalf("unsealed (%v) not equal to secret (%v)", unseal, secret)
	}
}
