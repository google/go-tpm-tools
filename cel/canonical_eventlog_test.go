package cel

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"io"
	"reflect"
	"testing"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
	pb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var measuredHashes = []crypto.Hash{crypto.SHA1, crypto.SHA256}

func TestCELEncodingDecoding(t *testing.T) {
	tpm := test.GetTPM(t)
	defer client.CheckedClose(t, tpm)

	cel := &CEL{}

	cosEvent := CosTlv{ImageDigestType, []byte("sha256:781d8dfdd92118436bd914442c8339e653b83f6bf3c1a7a98efcfb7c4fed7483")}
	appendOrFatal(t, cel, tpm, test.DebugPCR, measuredHashes, cosEvent)

	cosEvent2 := CosTlv{ImageRefType, []byte("docker.io/bazel/experimental/test:latest")}
	appendOrFatal(t, cel, tpm, test.ApplicationPCR, measuredHashes, cosEvent2)

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
	if decodedcel.Records[0].PCR != uint8(test.DebugPCR) {
		t.Errorf("pcr value mismatch")
	}
	if decodedcel.Records[1].PCR != uint8(test.ApplicationPCR) {
		t.Errorf("pcr value mismatch")
	}

	if !reflect.DeepEqual(decodedcel.Records, cel.Records) {
		t.Errorf("decoded CEL doesn't equal to the original one")
	}
}

func TestCELMeasureAndReplay(t *testing.T) {
	tpm := test.GetTPM(t)
	defer client.CheckedClose(t, tpm)

	err := tpm2.PCRReset(tpm, tpmutil.Handle(test.DebugPCR))
	if err != nil {
		t.Fatal(err)
	}
	err = tpm2.PCRReset(tpm, tpmutil.Handle(test.ApplicationPCR))
	if err != nil {
		t.Fatal(err)
	}

	cel := &CEL{}

	cosEvent := CosTlv{ImageRefType, []byte("docker.io/bazel/experimental/test:latest")}
	someEvent2 := make([]byte, 10)
	rand.Read(someEvent2)
	cosEvent2 := CosTlv{ImageDigestType, someEvent2}
	appendOrFatal(t, cel, tpm, test.DebugPCR, measuredHashes, cosEvent)
	appendOrFatal(t, cel, tpm, test.DebugPCR, measuredHashes, cosEvent2)

	appendOrFatal(t, cel, tpm, test.ApplicationPCR, measuredHashes, cosEvent2)
	appendOrFatal(t, cel, tpm, test.ApplicationPCR, measuredHashes, cosEvent)
	appendOrFatal(t, cel, tpm, test.ApplicationPCR, measuredHashes, cosEvent)

	replay(t, cel, tpm, measuredHashes,
		[]int{test.DebugPCR, test.ApplicationPCR}, true /*shouldSucceed*/)
	// Supersets should pass.
	replay(t, cel, tpm, measuredHashes,
		[]int{0, 13, 14, test.DebugPCR, 22, test.ApplicationPCR}, true /*shouldSucceed*/)
}

func TestCELReplayFailTamperedDigest(t *testing.T) {
	tpm := test.GetTPM(t)
	defer client.CheckedClose(t, tpm)

	cel := &CEL{}

	cosEvent := CosTlv{ImageRefType, []byte("docker.io/bazel/experimental/test:latest")}
	someEvent2 := make([]byte, 10)

	rand.Read(someEvent2)
	cosEvent2 := CosTlv{ImageDigestType, someEvent2}
	appendOrFatal(t, cel, tpm, test.DebugPCR, measuredHashes, cosEvent)
	appendOrFatal(t, cel, tpm, test.DebugPCR, measuredHashes, cosEvent2)

	appendOrFatal(t, cel, tpm, test.ApplicationPCR, measuredHashes, cosEvent2)
	appendOrFatal(t, cel, tpm, test.ApplicationPCR, measuredHashes, cosEvent)
	appendOrFatal(t, cel, tpm, test.ApplicationPCR, measuredHashes, cosEvent)

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
	appendOrFatal(t, cel, tpm, test.DebugPCR, measuredHashes, CosTlv{ImageRefType, someEvent})
	appendOrFatal(t, cel, tpm, test.ApplicationPCR, measuredHashes, CosTlv{ImageDigestType, someEvent2})
	replay(t, cel, tpm, measuredHashes,
		[]int{test.DebugPCR}, false /*shouldSucceed*/)
	replay(t, cel, tpm, measuredHashes,
		[]int{test.ApplicationPCR}, false /*shouldSucceed*/)
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
		pbPcr := &pb.PCRs{Hash: pb.HashAlgo(tpm2Hash),
			Pcrs: map[uint32][]byte{},
		}
		for index, val := range pcrMap {
			pbPcr.Pcrs[uint32(index)] = val
		}
		if err := cel.Replay(pbPcr); shouldSucceed && err != nil {
			t.Errorf("failed to replay CEL on %v bank: %v",
				pb.HashAlgo_name[int32(pbPcr.Hash)], err)
		}
	}
}

func appendOrFatal(t *testing.T, cel *CEL, tpm io.ReadWriteCloser, pcr int, hashAlgos []crypto.Hash, event Content) {
	if err := cel.AppendEvent(tpm, pcr, hashAlgos, event); err != nil {
		t.Fatalf("failed to append event: %v", err)
	}
}
