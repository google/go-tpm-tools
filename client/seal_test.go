package client_test

import (
	"bytes"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal"
)

func TestSeal(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	tests := []struct {
		name   string
		getSRK func(io.ReadWriter) (*client.Key, error)
	}{
		{"RSA", client.StorageRootKeyRSA},
		{"ECC", client.StorageRootKeyECC},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			srk, err := test.getSRK(rwc)
			if err != nil {
				t.Fatalf("can't create %s srk from template: %v", test.name, err)
			}
			defer srk.Close()

			secret := []byte("test")
			pcrToChange := internal.DebugPCR
			sel := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, pcrToChange}}
			sealed, err := srk.Seal(secret, client.SealCurrent{PCRSelection: sel})
			if err != nil {
				t.Fatalf("failed to seal: %v", err)
			}

			opts := client.CertifyCurrent{
				PCRSelection: tpm2.PCRSelection{
					Hash: tpm2.AlgSHA256,
					PCRs: []int{7},
				},
			}
			unseal, err := srk.Unseal(sealed, opts)
			if err != nil {
				t.Fatalf("failed to unseal: %v", err)
			}
			if !bytes.Equal(secret, unseal) {
				t.Fatalf("unsealed (%v) not equal to secret (%v)", unseal, secret)
			}

			extension := bytes.Repeat([]byte{0xAA}, sha256.Size)
			if err = tpm2.PCRExtend(rwc, tpmutil.Handle(pcrToChange), tpm2.AlgSHA256, extension, ""); err != nil {
				t.Fatalf("failed to extend pcr: %v", err)
			}

			// unseal should not succeed.
			if _, err = srk.Unseal(sealed, opts); err == nil {
				t.Fatalf("unseal should have caused an error: %v", err)
			}
		})
	}
}

func TestSelfReseal(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	key, err := client.StorageRootKeyRSA(rwc)
	if err != nil {
		t.Fatalf("can't create srk from template: %v", err)
	}
	defer key.Close()

	secret := []byte("test")
	pcrList := []int{0, 4, 7}
	sOpts := client.SealCurrent{
		PCRSelection: tpm2.PCRSelection{
			Hash: tpm2.AlgSHA256,
			PCRs: pcrList,
		},
	}

	sealed, err := key.Seal(secret, sOpts)
	if err != nil {
		t.Fatalf("failed to seal: %v", err)
	}

	cOpts := client.CertifyCurrent{
		PCRSelection: tpm2.PCRSelection{
			Hash: tpm2.AlgSHA256,
			PCRs: []int{7},
		},
	}
	unseal, err := key.Unseal(sealed, cOpts)
	if err != nil {
		t.Fatalf("failed to unseal: %v", err)
	}
	if !bytes.Equal(secret, unseal) {
		t.Errorf("unsealed (%v) not equal to secret (%v)", unseal, secret)
	}

	sealed, err = key.Reseal(sealed, cOpts, sOpts)
	if err != nil {
		t.Fatalf("failed to reseal: %v", err)
	}

	unseal, err = key.Unseal(sealed, cOpts)
	if err != nil {
		t.Fatalf("failed to unseal after resealing: %v", err)
	}
	if !bytes.Equal(secret, unseal) {
		t.Errorf("unsealed (%v) not equal to secret (%v)", unseal, secret)
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
	defer client.CheckedClose(t, rwc)

	pcrNum := internal.DebugPCR
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
	defer client.CheckedClose(t, rwc)

	key, err := client.StorageRootKeyRSA(rwc)
	if err != nil {
		t.Fatalf("can't create srk from template: %v", err)
	}
	defer key.Close()

	secret := []byte("test")
	pcrToChange := internal.DebugPCR
	sel := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, pcrToChange}}
	sealed, err := key.Seal(secret, client.SealCurrent{PCRSelection: sel})
	if err != nil {
		t.Fatalf("failed to seal: %v", err)
	}

	opts := client.CertifyCurrent{
		PCRSelection: sel,
	}
	unseal, err := key.Unseal(sealed, opts)
	if err != nil {
		t.Fatalf("failed to unseal: %v", err)
	}
	if !bytes.Equal(secret, unseal) {
		t.Fatalf("unsealed (%v) not equal to secret (%v)", unseal, secret)
	}

	// create a new set of PCRs value for modification
	predictedPcrsValue, err := client.ReadPCRs(rwc, sel)
	if err != nil {
		t.Fatalf("failed to read PCRs value: %v", err)
	}
	// change pcr value to the predicted future value for resealing
	extensions := [][]byte{bytes.Repeat([]byte{0xAA}, sha256.Size)}
	predictedPcrsValue.GetPcrs()[uint32(pcrToChange)] = computePCRValue(predictedPcrsValue.GetPcrs()[uint32(pcrToChange)], extensions)

	resealed, err := key.Reseal(sealed, opts, client.SealTarget{predictedPcrsValue})
	if err != nil {
		t.Fatalf("failed to reseal: %v", err)
	}

	// unseal should not succeed since pcr has not been extended.
	if _, err = key.Unseal(resealed, nil); err == nil {
		t.Fatalf("unseal should have failed: %v", err)
	}

	// save the current PCR value for certification before extend the PCRs
	oldPcrsValue, err := client.ReadPCRs(rwc, sel)
	if err != nil {
		t.Fatalf("failed to read PCRs value: %v", err)
	}
	for _, extension := range extensions {
		err = tpm2.PCRExtend(rwc, tpmutil.Handle(pcrToChange), tpm2.AlgSHA256, extension, "")
		if err != nil {
			t.Fatalf("failed to extend pcr: %v", err)
		}
	}

	// unseal should fail if certify to current PCRs value, as one PCR has changed
	_, err = key.Unseal(resealed, client.CertifyCurrent{PCRSelection: sel})
	if err == nil {
		t.Fatalf("unseal should fail since the certify PCRs have changed.")
	}

	// certify to original PCRs value (PCRs value when do the sealing) will work
	unseal, err = key.Unseal(resealed, client.CertifyExpected{oldPcrsValue})
	if err != nil {
		t.Fatalf("failed to unseal: %v", err)
	}
	if !bytes.Equal(secret, unseal) {
		t.Errorf("unsealed (%v) not equal to secret (%v)", unseal, secret)
	}
}

func TestSealResealWithEmptyPCRs(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	key, err := client.StorageRootKeyRSA(rwc)
	if err != nil {
		t.Fatalf("can't create srk from template: %v", err)
	}
	defer key.Close()

	secret := []byte("test")
	pcrToChange := internal.DebugPCR
	sealed, err := key.Seal(secret, nil)
	if err != nil {
		t.Fatalf("failed to seal: %v", err)
	}
	opts := client.CertifyCurrent{
		PCRSelection: tpm2.PCRSelection{
			Hash: tpm2.AlgSHA256,
			PCRs: []int{pcrToChange},
		},
	}
	unseal, err := key.Unseal(sealed, opts)
	if err != nil {
		t.Fatalf("failed to unseal: %v", err)
	}
	if !bytes.Equal(secret, unseal) {
		t.Fatalf("unsealed (%v) not equal to secret (%v)", unseal, secret)
	}

	extension := bytes.Repeat([]byte{0xAA}, sha256.Size)
	if err = tpm2.PCRExtend(rwc, tpmutil.Handle(pcrToChange), tpm2.AlgSHA256, extension, ""); err != nil {
		t.Fatalf("failed to extend pcr: %v", err)
	}

	// unseal should fail as the PCR has changed (not as same as when sealing)
	_, err = key.Unseal(sealed, opts)
	if err == nil {
		t.Fatalf("unseal should fail as PCR 7 changed")
	}

	// reseal should succeed as CertifyOpts is nil
	sealed, err = key.Reseal(sealed, nil, nil)
	if err != nil {
		t.Fatalf("failed to reseal: %v", err)
	}

	// unseal should success as the above Reseal() "refresh" the Certify PCRs.
	unseal, err = key.Unseal(sealed, opts)
	if err != nil {
		t.Errorf("failed to unseal: %v", err)
	}
	if !bytes.Equal(secret, unseal) {
		t.Fatalf("unsealed (%v) not equal to secret (%v)", unseal, secret)
	}
}

func BenchmarkSeal(b *testing.B) {
	rwc := internal.GetTPM(b)
	defer client.CheckedClose(b, rwc)

	pcrSel7 := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7}}
	sOptsPCR7 := client.SealCurrent{PCRSelection: pcrSel7}
	cOptsPCR7 := client.CertifyCurrent{PCRSelection: pcrSel7}
	benchmarks := []struct {
		name   string
		sOpts  client.SealOpts
		cOpts  client.CertifyOpts
		getKey func(io.ReadWriter) (*client.Key, error)
	}{
		{"SRK-ECC-SealPCR7-CertifyPCR7", sOptsPCR7, cOptsPCR7, client.StorageRootKeyECC},
		{"SRK-ECC-nil-CertifyPCR7", nil, cOptsPCR7, client.StorageRootKeyECC},
		{"SRK-ECC-SealPCR7-nil", sOptsPCR7, nil, client.StorageRootKeyECC},
		{"SRK-ECC-nil-nil", nil, nil, client.StorageRootKeyECC},
		{"SRK-RSA-SealPCR7-CertifyPCR7", sOptsPCR7, cOptsPCR7, client.StorageRootKeyRSA},
		{"SRK-RSA-nil-CertifyPCR7", nil, cOptsPCR7, client.StorageRootKeyRSA},
		{"SRK-RSA-SealPCR7-nil", sOptsPCR7, nil, client.StorageRootKeyRSA},
		{"SRK-RSA-nil-nil", nil, nil, client.StorageRootKeyRSA},
	}

	for _, bm := range benchmarks {
		key, err := bm.getKey(rwc)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(bm.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				blob, err := key.Seal([]byte("test123"), bm.sOpts)
				if err != nil {
					b.Fatal(err)
				}
				if _, err = key.Unseal(blob, bm.cOpts); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
