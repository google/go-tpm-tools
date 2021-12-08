package cel

import (
	"bytes"
	"crypto"
	"io"
	"reflect"
	"testing"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
)

func TestCELEncodingDecoding(t *testing.T) {
	tpm := test.GetTPM(t)
	defer client.CheckedClose(t, tpm)

	hashAlgoList := []crypto.Hash{crypto.SHA256, crypto.SHA1, crypto.SHA512}
	cel := &CEL{}

	someEvent := make([]byte, 10)
	cosEvent := CosTlv{someEvent}
	appendOrFatal(t, cel, tpm, test.DebugPCR, hashAlgoList, cosEvent)

	cosEvent2 := CosTlv{someEvent}
	appendOrFatal(t, cel, tpm, test.ApplicationPCR, hashAlgoList, cosEvent2)

	var buf bytes.Buffer
	if err := cel.EncodeCEL(&buf); err != nil {
		t.Fatal(err)
	}
	decodedcel, err := DecodeToCEL(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(decodedcel.Records) != 2 {
		t.Errorf("should have three records")
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

	digestsMap := decodedcel.Records[0].Digests
	if len(digestsMap[crypto.SHA256]) != 32 {
		t.Errorf("SHA256 digest length doesn't match")
	}
	if len(digestsMap[crypto.SHA1]) != 20 {
		t.Errorf("SHA1 digest length doesn't match")
	}
	if !reflect.DeepEqual(decodedcel.Records, cel.Records) {
		t.Errorf("decoded CEL doesn't equal to the original one")
	}
}

func appendOrFatal(t *testing.T, cel *CEL, tpm io.ReadWriteCloser, pcr int, hashAlgos []crypto.Hash, event Content) {
	if err := cel.AppendEvent(tpm, pcr, hashAlgos, event); err != nil {
		t.Fatalf("failed to append event: %v", err)
	}
}
