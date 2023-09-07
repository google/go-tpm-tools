package client_test

import (
	"bytes"
	"crypto/sha256"
	"io"
	"reflect"
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
	pb "github.com/google/go-tpm-tools/proto/tpm"
)

func TestSeal(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	keys := []struct {
		name   string
		getSRK func(io.ReadWriter) (*client.Key, error)
	}{
		{"RSA", client.StorageRootKeyRSA},
		{"ECC", client.StorageRootKeyECC},
	}
	for _, key := range keys {
		t.Run(key.name, func(t *testing.T) {
			srk, err := key.getSRK(rwc)
			if err != nil {
				t.Fatalf("can't create %s srk from template: %v", key.name, err)
			}
			defer srk.Close()

			secret := []byte("test")
			pcrToChange := test.DebugPCR
			sel := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, pcrToChange}}
			sealed, err := srk.Seal(secret, client.SealOpts{Current: sel})
			if err != nil {
				t.Fatalf("failed to seal: %v", err)
			}

			opts := client.UnsealOpts{
				CertifyCurrent: tpm2.PCRSelection{
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
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	key, err := client.StorageRootKeyRSA(rwc)
	if err != nil {
		t.Fatalf("can't create srk from template: %v", err)
	}
	defer key.Close()

	secret := []byte("test")
	pcrList := []int{0, 4, 7}
	sOpts := client.SealOpts{
		Current: tpm2.PCRSelection{
			Hash: tpm2.AlgSHA256,
			PCRs: pcrList,
		},
	}

	sealed, err := key.Seal(secret, sOpts)
	if err != nil {
		t.Fatalf("failed to seal: %v", err)
	}

	uOpts := client.UnsealOpts{
		CertifyCurrent: tpm2.PCRSelection{
			Hash: tpm2.AlgSHA256,
			PCRs: []int{7},
		},
	}
	unseal, err := key.Unseal(sealed, uOpts)
	if err != nil {
		t.Fatalf("failed to unseal: %v", err)
	}
	if !bytes.Equal(secret, unseal) {
		t.Errorf("unsealed (%v) not equal to secret (%v)", unseal, secret)
	}

	sealed, err = key.Reseal(sealed, uOpts, sOpts)
	if err != nil {
		t.Fatalf("failed to reseal: %v", err)
	}

	unseal, err = key.Unseal(sealed, uOpts)
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
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	pcrNum := test.DebugPCR
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
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	key, err := client.StorageRootKeyRSA(rwc)
	if err != nil {
		t.Fatalf("can't create srk from template: %v", err)
	}
	defer key.Close()

	secret := []byte("test")
	pcrToChange := test.DebugPCR
	sel := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, pcrToChange}}
	sealed, err := key.Seal(secret, client.SealOpts{Current: sel})
	if err != nil {
		t.Fatalf("failed to seal: %v", err)
	}

	uOpts := client.UnsealOpts{
		CertifyCurrent: sel,
	}
	unseal, err := key.Unseal(sealed, uOpts)
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

	sOpts := client.SealOpts{Target: predictedPcrsValue}
	resealed, err := key.Reseal(sealed, uOpts, sOpts)
	if err != nil {
		t.Fatalf("failed to reseal: %v", err)
	}

	// unseal should not succeed since pcr has not been extended.
	if _, err = key.Unseal(resealed, client.UnsealOpts{}); err == nil {
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

	// unseal should fail when certifying current PCR values, as one PCR has changed
	_, err = key.Unseal(resealed, client.UnsealOpts{CertifyCurrent: sel})
	if err == nil {
		t.Fatalf("unseal should fail since the certify PCRs have changed.")
	}

	// certify original PCR values (PCR values at seal-time) will work
	unseal, err = key.Unseal(resealed, client.UnsealOpts{CertifyExpected: oldPcrsValue})
	if err != nil {
		t.Fatalf("failed to unseal: %v", err)
	}
	if !bytes.Equal(secret, unseal) {
		t.Errorf("unsealed (%v) not equal to secret (%v)", unseal, secret)
	}
}

func TestSealResealWithEmptyPCRs(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	key, err := client.StorageRootKeyRSA(rwc)
	if err != nil {
		t.Fatalf("can't create srk from template: %v", err)
	}
	defer key.Close()

	secret := []byte("test")
	pcrToChange := test.DebugPCR
	sealed, err := key.Seal(secret, client.SealOpts{})
	if err != nil {
		t.Fatalf("failed to seal: %v", err)
	}
	opts := client.UnsealOpts{
		CertifyCurrent: tpm2.PCRSelection{
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

	// reseal should succeed as UnsealOpts is empty
	sealed, err = key.Reseal(sealed, client.UnsealOpts{}, client.SealOpts{})
	if err != nil {
		t.Fatalf("failed to reseal: %v", err)
	}

	// unseal should success as the above Reseal() "refreshes" the certify PCRs.
	unseal, err = key.Unseal(sealed, opts)
	if err != nil {
		t.Errorf("failed to unseal: %v", err)
	}
	if !bytes.Equal(secret, unseal) {
		t.Fatalf("unsealed (%v) not equal to secret (%v)", unseal, secret)
	}
}

func BenchmarkSeal(b *testing.B) {
	rwc := test.GetTPM(b)
	defer client.CheckedClose(b, rwc)

	pcrSel7 := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7}}
	sOptsPCR7 := client.SealOpts{Current: pcrSel7}
	uOptsPCR7 := client.UnsealOpts{CertifyCurrent: pcrSel7}
	benchmarks := []struct {
		name   string
		sOpts  client.SealOpts
		uOpts  client.UnsealOpts
		getKey func(io.ReadWriter) (*client.Key, error)
	}{
		{"SRK-ECC-SealPCR7-UnsealPCR7", sOptsPCR7, uOptsPCR7, client.StorageRootKeyECC},
		{"SRK-ECC-SealEmpty-UnsealPCR7", client.SealOpts{}, uOptsPCR7, client.StorageRootKeyECC},
		{"SRK-ECC-SealPCR7-UnsealEmpty", sOptsPCR7, client.UnsealOpts{}, client.StorageRootKeyECC},
		{"SRK-ECC-SealEmpty-UnsealEmpty", client.SealOpts{}, client.UnsealOpts{}, client.StorageRootKeyECC},
		{"SRK-RSA-SealPCR7-UnsealPCR7", sOptsPCR7, uOptsPCR7, client.StorageRootKeyRSA},
		{"SRK-RSA-SealEmpty-UnsealPCR7", client.SealOpts{}, uOptsPCR7, client.StorageRootKeyRSA},
		{"SRK-RSA-SealPCR7-UnsealEmpty", sOptsPCR7, client.UnsealOpts{}, client.StorageRootKeyRSA},
		{"SRK-RSA-SealEmpty-UnsealEmpty", client.SealOpts{}, client.UnsealOpts{}, client.StorageRootKeyRSA},
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
				if _, err = key.Unseal(blob, bm.uOpts); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
func TestSealOpts(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	emptySet := map[uint32]struct{}{}
	srk, err := client.StorageRootKeyECC(rwc)
	if err != nil {
		t.Fatalf("failed to create SRK: %v", err)
	}

	opts := []struct {
		name         string
		current      tpm2.PCRSelection
		target       *pb.PCRs
		expectedPcrs map[uint32]struct{}
	}{
		{"CurrentEmpty-TargetNil", tpm2.PCRSelection{}, nil, emptySet},
		{"CurrentEmpty7-TargetNil", tpm2.PCRSelection{}, nil, emptySet},
		{"CurrentEmpty-TargetEmpty", tpm2.PCRSelection{}, &pb.PCRs{}, emptySet},
		{"CurrentSHA1Empty-TargetSHA256Empty",
			tpm2.PCRSelection{Hash: tpm2.AlgSHA1},
			&pb.PCRs{Hash: pb.HashAlgo_SHA256},
			emptySet},
		{"CurrentSHA256Empty-TargetSHA1Empty",
			tpm2.PCRSelection{Hash: tpm2.AlgSHA256},
			&pb.PCRs{Hash: pb.HashAlgo_SHA1},
			emptySet},
		{"CurrentSHA2567-TargetSHA1Empty",
			tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7}},
			&pb.PCRs{Hash: pb.HashAlgo_SHA1},
			map[uint32]struct{}{7: {}}},
		{"Current7-TargetPCR0,4",
			tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{0, 7}},
			&pb.PCRs{Hash: pb.HashAlgo_SHA256,
				Pcrs: map[uint32][]byte{4: {0x00}}},
			map[uint32]struct{}{
				0: {},
				4: {},
				7: {},
			}},
	}

	sliceToSet := func(a []uint32) map[uint32]struct{} {
		ret := make(map[uint32]struct{})
		for _, val := range a {
			ret[val] = struct{}{}
		}
		return ret
	}
	for _, testcase := range opts {
		t.Run(testcase.name, func(t *testing.T) {
			sOpts := client.SealOpts{Current: testcase.current, Target: testcase.target}
			sealed, err := srk.Seal([]byte("secretzz"), sOpts)
			if err != nil {
				t.Errorf("error calling Seal with SealOpts: %v", err)
			}
			outPcrsMap := sliceToSet(sealed.Pcrs)
			if !reflect.DeepEqual(outPcrsMap, testcase.expectedPcrs) {
				t.Errorf("received PCRs (%v) do not match expected PCRs (%v)",
					outPcrsMap, testcase.expectedPcrs)
			}
		})
	}

	// Run empty SealOpts.
	_, err = srk.Seal([]byte("secretzz"), client.SealOpts{})
	if err != nil {
		t.Errorf("error calling Seal with SealOpts: %v", err)
	}
}
func TestSealAndUnsealOptsFail(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	srk, err := client.StorageRootKeyECC(rwc)
	if err != nil {
		t.Fatalf("failed to create SRK: %v", err)
	}

	pcrSel7 := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7}}
	pcrMap7 := map[uint32][]byte{7: {0x01, 0x02}}
	pbPcr7 := &pb.PCRs{Hash: pb.HashAlgo_SHA256, Pcrs: pcrMap7}
	opts := []struct {
		name    string
		current tpm2.PCRSelection
		target  *pb.PCRs
	}{
		{"CurrentSHA256-TargetSHA1", pcrSel7, &pb.PCRs{Hash: pb.HashAlgo_SHA1, Pcrs: pcrMap7}},
		{"Current-TargetPCROverlap", pcrSel7, pbPcr7},
		{"Current-TargetPCROverlapMultiple", tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{0, 4, 7, 8}},
			&pb.PCRs{Hash: pb.HashAlgo_SHA256, Pcrs: map[uint32][]byte{0: {}, 4: {0x00}, 9: {0x01, 0x02}}}},
	}

	for _, testcase := range opts {
		t.Run("Seal"+testcase.name, func(t *testing.T) {
			sOpts := client.SealOpts{Current: testcase.current,
				Target: testcase.target}
			_, err := srk.Seal([]byte("secretzz"), sOpts)
			if err == nil {
				t.Errorf("expected failure calling SealOpts")
			}
		})
	}

	sealed, err := srk.Seal([]byte("secretzz"), client.SealOpts{})
	if err != nil {
		t.Fatalf("failed to seal: %v", err)
	}
	for _, testcase := range opts {
		t.Run("Unseal"+testcase.name, func(t *testing.T) {
			uOpts := client.UnsealOpts{CertifyCurrent: testcase.current,
				CertifyExpected: testcase.target}
			_, err := srk.Unseal(sealed, uOpts)
			if err == nil {
				t.Errorf("expected failure calling SealOpts")
			}
		})
	}
}
