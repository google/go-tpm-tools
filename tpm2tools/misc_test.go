package tpm2tools

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"testing"

	"github.com/google/go-tpm-tools/internal"
	"github.com/google/go-tpm/tpm2"
)

func TestReadPCRsSHA1(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer CheckedClose(t, rwc)

	proto, err := ReadPCRs(rwc, []int{0}, tpm2.AlgSHA1)
	if err != nil {
		t.Fatalf("failed to read pcrs %v", err)
	}

	expected := bytes.Repeat([]byte{0x00}, sha1.Size)

	if !bytes.Equal(proto.Pcrs[0], expected) {
		t.Fatalf("%v not equal to expected %v", proto.Pcrs[0], expected)
	}
}

func TestReadPCRsSHA256(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer CheckedClose(t, rwc)

	proto, err := ReadPCRs(rwc, []int{0}, tpm2.AlgSHA256)
	if err != nil {
		t.Fatalf("failed to read pcrs %v", err)
	}

	expected := bytes.Repeat([]byte{0x00}, sha256.Size)

	if !bytes.Equal(proto.Pcrs[0], expected) {
		t.Fatalf("%v not equal to expected %v", proto.Pcrs[0], expected)
	}
}
