package cel

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
	pb "github.com/google/go-tpm-tools/proto/attest"
)

func TestCosEventlog(t *testing.T) {
	tpm := test.GetTPM(t)
	defer client.CheckedClose(t, tpm)

	hashAlgoList := []crypto.Hash{crypto.SHA256, crypto.SHA1, crypto.SHA512}
	cel := &CEL{}

	testEvents := []struct {
		cosNestedEventType CosType
		pcr                int
		eventPayload       []byte
	}{
		{ImageRefType, test.DebugPCR, []byte("docker.io/bazel/experimental/test:latest")},
		{ImageDigestType, test.DebugPCR, []byte("sha256:781d8dfdd92118436bd914442c8339e653b83f6bf3c1a7a98efcfb7c4fed7483")},
		{RestartPolicyType, test.DebugPCR, []byte(pb.RestartPolicy_Never.String())},
	}

	for _, testEvent := range testEvents {
		cos := CosTlv{testEvent.cosNestedEventType, testEvent.eventPayload}
		if err := cel.AppendEvent(tpm, testEvent.pcr, hashAlgoList, cos); err != nil {
			t.Fatal(err.Error())
		}
	}

	var buf bytes.Buffer
	if err := cel.EncodeCEL(&buf); err != nil {
		t.Fatal(err)
	}
	decodedcel, err := DecodeToCEL(&buf)
	if err != nil {
		t.Fatal(err)
	}

	if len(decodedcel.Records) != 3 {
		t.Errorf("should have three records")
	}

	for i, testEvent := range testEvents {
		extractedCos, err := decodedcel.Records[i].Content.ParseToCosTlv()
		if err != nil {
			t.Fatal(err)
		}

		want := CosTlv{testEvent.cosNestedEventType, testEvent.eventPayload}
		if !cmp.Equal(extractedCos, want) {
			t.Errorf("decoded COS TLV got %+v, want %+v", extractedCos, want)
		}
	}
}
