package cel

import (
	"bytes"
	"crypto"
	"reflect"
	"testing"
)

func TestCELEncodingDecoding(t *testing.T) {
	hashAlgoList := []crypto.Hash{crypto.SHA256, crypto.SHA1, crypto.SHA512}
	cel := &CEL{}

	someEvent := make([]byte, 10)
	cosEvent := CosTlv{someEvent}
	err := cel.AppendEvent(nil, 13, hashAlgoList, cosEvent)
	if err != nil {
		t.Fatal(err.Error())
	}

	cosEvent2 := CosTlv{someEvent}
	err = cel.AppendEvent(nil, 14, hashAlgoList, cosEvent2)
	if err != nil {
		t.Fatal(err.Error())
	}

	var buf bytes.Buffer
	err = cel.EncodeCEL(&buf)
	if err != nil {
		t.Fatalf(err.Error())
	}
	decodedcel, err := DecodeToCEL(&buf)
	if err != nil {
		t.Fatalf(err.Error())
	}
	if len(decodedcel.Records) != 2 {
		t.Errorf("should have two records")
	}
	if recnum, err := UnmarshalRecNum(decodedcel.Records[0].RECNUM); err != nil || recnum != uint64(0) {
		t.Errorf("recnum mismatch")
	}
	if recnum, err := UnmarshalRecNum(decodedcel.Records[1].RECNUM); err != nil || recnum != uint64(1) {
		t.Errorf("recnum mismatch")
	}
	if pcr, err := UnmarshalPCR(decodedcel.Records[0].PCR); err != nil || pcr != uint8(13) {
		t.Errorf("pcr value mismatch")
	}
	if pcr, err := UnmarshalPCR(decodedcel.Records[1].PCR); err != nil || pcr != uint8(14) {
		t.Errorf("pcr value mismatch")
	}

	digestsMap, err := UnmarshalDigests(decodedcel.Records[0].Digests)
	if err != nil {
		t.Error(err)
	}
	if len(digestsMap[crypto.SHA256]) != 32 {
		t.Errorf("SHA256 digest length doesn't match")
	}
	if len(digestsMap[crypto.SHA1]) != 20 {
		t.Errorf("SHA1 digest length doesn't match")
	}
	if reflect.DeepEqual(decodedcel.Records, (*cel).Records) == false {
		t.Errorf("decoded CEL doesn't equal to the original one")
	}
}
