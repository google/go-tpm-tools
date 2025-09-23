package cel

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"io"
	"reflect"
	"testing"

	"github.com/google/go-configfs-tsm/configfs/configfsi"
	"github.com/google/go-configfs-tsm/configfs/fakertmr"
	configfstsmrtmr "github.com/google/go-configfs-tsm/rtmr"
	"github.com/google/go-eventlog/proto/state"
	"github.com/google/go-eventlog/register"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var measuredHashes = []crypto.Hash{crypto.SHA1, crypto.SHA256}

func TestCELEncodingDecoding(t *testing.T) {
	tpm := test.GetTPM(t)
	defer client.CheckedClose(t, tpm)

	cel := &CEL{}

	cosEvent := CosTlv{ImageDigestType, []byte("sha256:781d8dfdd92118436bd914442c8339e653b83f6bf3c1a7a98efcfb7c4fed7483")}
	appendPcrEventOrFatal(t, cel, tpm, test.DebugPCR, cosEvent)

	cosEvent2 := CosTlv{ImageRefType, []byte("docker.io/bazel/experimental/test:latest")}
	appendPcrEventOrFatal(t, cel, tpm, test.ApplicationPCR, cosEvent2)

	var buf bytes.Buffer
	if err := cel.EncodeCEL(&buf); err != nil {
		t.Fatal(err)
	}
	decodedcel, err := DecodeToCEL(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(decodedcel.Records) != 2 {
		t.Errorf("should have two records")
	}
	if decodedcel.Records[0].RecNum != 0 {
		t.Errorf("recnum mismatch")
	}
	if decodedcel.Records[1].RecNum != 1 {
		t.Errorf("recnum mismatch")
	}
	if decodedcel.Records[0].IndexType != PCRTypeValue {
		t.Errorf("index type mismatch")
	}
	if decodedcel.Records[0].Index != uint8(test.DebugPCR) {
		t.Errorf("pcr value mismatch")
	}
	if decodedcel.Records[1].IndexType != PCRTypeValue {
		t.Errorf("index type mismatch")
	}
	if decodedcel.Records[1].Index != uint8(test.ApplicationPCR) {
		t.Errorf("pcr value mismatch")
	}

	if !reflect.DeepEqual(decodedcel.Records, cel.Records) {
		t.Errorf("decoded CEL doesn't equal to the original one")
	}
}

func TestCELMeasureAndReplay(t *testing.T) {
	tpm := test.GetTPM(t)
	defer client.CheckedClose(t, tpm)

	fakeRTMR := fakertmr.CreateRtmrSubsystem(t.TempDir())

	err := tpm2.PCRReset(tpm, tpmutil.Handle(test.DebugPCR))
	if err != nil {
		t.Fatal(err)
	}
	err = tpm2.PCRReset(tpm, tpmutil.Handle(test.ApplicationPCR))
	if err != nil {
		t.Fatal(err)
	}

	cel := &CEL{}
	celRTMR := &CEL{}

	cosEvent := CosTlv{ImageRefType, []byte("docker.io/bazel/experimental/test:latest")}

	someEvent2 := make([]byte, 10)
	rand.Read(someEvent2)
	cosEvent2 := CosTlv{ImageDigestType, someEvent2}

	appendPcrEventOrFatal(t, cel, tpm, test.DebugPCR, cosEvent)
	appendRtmrEventOrFatal(t, celRTMR, fakeRTMR, CosRTMR, cosEvent)

	appendPcrEventOrFatal(t, cel, tpm, test.DebugPCR, cosEvent2)
	appendRtmrEventOrFatal(t, celRTMR, fakeRTMR, CosRTMR, cosEvent)

	appendPcrEventOrFatal(t, cel, tpm, test.ApplicationPCR, cosEvent2)
	appendRtmrEventOrFatal(t, celRTMR, fakeRTMR, CosRTMR, cosEvent2)

	appendPcrEventOrFatal(t, cel, tpm, test.ApplicationPCR, cosEvent)
	appendRtmrEventOrFatal(t, celRTMR, fakeRTMR, CosRTMR, cosEvent)

	appendPcrEventOrFatal(t, cel, tpm, test.ApplicationPCR, cosEvent)
	appendRtmrEventOrFatal(t, celRTMR, fakeRTMR, CosRTMR, cosEvent)

	replay(t, cel, tpm, measuredHashes,
		[]int{test.DebugPCR, test.ApplicationPCR}, true /*shouldSucceed*/)
	// Supersets should pass.
	replay(t, cel, tpm, measuredHashes,
		[]int{0, 13, 14, test.DebugPCR, 22, test.ApplicationPCR}, true /*shouldSucceed*/)

	replayRTMR(t, celRTMR, fakeRTMR, []int{0, 1, 2, 3}, true /*shouldSucceed*/)
}

func TestCELReplayFailTamperedDigest(t *testing.T) {
	tpm := test.GetTPM(t)
	defer client.CheckedClose(t, tpm)

	cel := &CEL{}

	cosEvent := CosTlv{ImageRefType, []byte("docker.io/bazel/experimental/test:latest")}
	someEvent2 := make([]byte, 10)
	rand.Read(someEvent2)
	cosEvent2 := CosTlv{ImageDigestType, someEvent2}

	appendPcrEventOrFatal(t, cel, tpm, test.DebugPCR, cosEvent)
	appendPcrEventOrFatal(t, cel, tpm, test.DebugPCR, cosEvent2)
	appendPcrEventOrFatal(t, cel, tpm, test.ApplicationPCR, cosEvent2)
	appendPcrEventOrFatal(t, cel, tpm, test.ApplicationPCR, cosEvent)
	appendPcrEventOrFatal(t, cel, tpm, test.ApplicationPCR, cosEvent)

	modifiedRecord := cel.Records[3]
	for hash := range modifiedRecord.Digests {
		newDigest := make([]byte, hash.Size())
		rand.Read(newDigest)
		modifiedRecord.Digests[hash] = newDigest
	}
	replay(t, cel, tpm, measuredHashes,
		[]int{test.DebugPCR, test.ApplicationPCR}, false /*shouldSucceed*/)
}

func TestCELReplayEmpty(t *testing.T) {
	tpm := test.GetTPM(t)
	defer client.CheckedClose(t, tpm)

	cel := &CEL{}
	replay(t, cel, tpm, []crypto.Hash{crypto.SHA1, crypto.SHA256},
		[]int{test.DebugPCR, test.ApplicationPCR}, true /*shouldSucceed*/)
}

func TestCELReplayFailMissingPCRsInBank(t *testing.T) {
	tpm := test.GetTPM(t)
	defer client.CheckedClose(t, tpm)

	cel := &CEL{}

	someEvent := make([]byte, 10)
	someEvent2 := make([]byte, 10)
	rand.Read(someEvent2)

	appendPcrEventOrFatal(t, cel, tpm, test.DebugPCR, CosTlv{ImageRefType, someEvent})
	appendPcrEventOrFatal(t, cel, tpm, test.ApplicationPCR, CosTlv{ImageDigestType, someEvent2})

	replay(t, cel, tpm, measuredHashes,
		[]int{test.DebugPCR}, false /*shouldSucceed*/)
	replay(t, cel, tpm, measuredHashes,
		[]int{test.ApplicationPCR}, false /*shouldSucceed*/)
}

func TestCELMeasureToAllPCRBanks(t *testing.T) {
	tpm := test.GetTPM(t)
	defer client.CheckedClose(t, tpm)

	pcrs, err := client.ReadAllPCRs(tpm)
	if err != nil {
		t.Fatal(err)
	}
	for _, bank := range pcrs {
		// make sure debug pcr is empty before the append
		if !isZeroBytes(bank.Pcrs[uint32(test.DebugPCR)]) {
			t.Fatalf("PCR %d in bank %s is not empty before appending event", test.DebugPCR, bank.Hash.String())
		}
	}

	cel := &CEL{}
	someEvent := make([]byte, 10)
	appendPcrEventOrFatal(t, cel, tpm, test.DebugPCR, CosTlv{ImageRefType, someEvent})

	pcrs, err = client.ReadAllPCRs(tpm)
	if err != nil {
		t.Fatal(err)
	}
	for _, bank := range pcrs {
		// make sure debug pcr is NOT empty after the append
		if isZeroBytes(bank.Pcrs[uint32(test.DebugPCR)]) {
			t.Fatalf("PCR %d in bank %s is empty after appending event", test.DebugPCR, bank.Hash.String())
		}
	}
}

func isZeroBytes(bs []byte) bool {
	allZeros := make([]byte, len(bs))
	return bytes.Equal(allZeros, bs)
}

func replay(t *testing.T, cel *CEL, tpm io.ReadWriteCloser, measuredHashes []crypto.Hash, pcrs []int, shouldSucceed bool) {
	for _, hash := range measuredHashes {
		tpm2Hash, err := tpm2.HashToAlgorithm(hash)
		if err != nil {
			t.Fatal(err)
		}
		pcrMap, err := tpm2.ReadPCRs(tpm, tpm2.PCRSelection{Hash: tpm2Hash, PCRs: pcrs})
		if err != nil {
			t.Fatal(err)
		}

		pcrBank := register.PCRBank{TCGHashAlgo: state.HashAlgo(tpm2Hash)}
		for index, val := range pcrMap {
			pcrBank.PCRs = append(pcrBank.PCRs, register.PCR{
				Index:     index,
				Digest:    val,
				DigestAlg: hash})
		}

		if err := cel.Replay(pcrBank); shouldSucceed && err != nil {
			t.Errorf("failed to replay CEL on %v bank: %v",
				hash, err)
		}
	}
}

func replayRTMR(t *testing.T, cel *CEL, rtmr *fakertmr.RtmrSubsystem, rtmrs []int, shouldSucceed bool) {
	rtmrBank := register.RTMRBank{}

	// RTMR 0 to 3
	for _, rtmrIndex := range rtmrs {
		digest, err := configfstsmrtmr.GetDigest(rtmr, rtmrIndex)
		if err != nil {
			t.Fatal(err)
		}

		rtmrBank.RTMRs = append(rtmrBank.RTMRs, register.RTMR{
			Index:  rtmrIndex,
			Digest: digest.Digest})
	}

	if err := cel.Replay(rtmrBank); shouldSucceed && err != nil {
		t.Errorf("failed to replay RTMR: %v", err)
	}
}

func appendPcrEventOrFatal(t *testing.T, cel *CEL, tpm io.ReadWriteCloser, pcr int, event Content) {
	if err := cel.AppendEventPCR(tpm, pcr, event); err != nil {
		t.Fatalf("failed to append PCR event: %v", err)
	}
}

func appendRtmrEventOrFatal(t *testing.T, cel *CEL, rtmrClient configfsi.Client, rtmr int, event Content) {
	if err := cel.AppendEventRTMR(rtmrClient, rtmr, event); err != nil {
		t.Fatalf("failed to append RTMR event: %v", err)
	}
}
