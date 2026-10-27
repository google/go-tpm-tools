package internal

import (
	"bytes"
	"crypto"
	"math"
	"strings"
	"testing"

	pb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/legacy/tpm2"
)

func TestHasSamePCRSelection(t *testing.T) {
	var subtests = []struct {
		pcrs        *pb.PCRs
		pcrSel      tpm2.PCRSelection
		expectedRes bool
	}{
		{&pb.PCRs{}, tpm2.PCRSelection{}, true},
		{&pb.PCRs{Hash: pb.HashAlgo(tpm2.AlgSHA256), Pcrs: map[uint32][]byte{1: {}}},
			tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{1}}, true},
		{&pb.PCRs{Hash: pb.HashAlgo(tpm2.AlgSHA256), Pcrs: map[uint32][]byte{}},
			tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{}}, true},
		{&pb.PCRs{Hash: pb.HashAlgo(tpm2.AlgSHA256), Pcrs: map[uint32][]byte{1: {}}},
			tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{4}}, false},
		{&pb.PCRs{Hash: pb.HashAlgo(tpm2.AlgSHA256), Pcrs: map[uint32][]byte{1: {}, 4: {}}},
			tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{4}}, false},
		{&pb.PCRs{Hash: pb.HashAlgo(tpm2.AlgSHA256), Pcrs: map[uint32][]byte{1: {}, 2: {}}},
			tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{1, 2}}, false},
	}
	for _, subtest := range subtests {
		if SamePCRSelection(subtest.pcrs, subtest.pcrSel) != subtest.expectedRes {
			t.Errorf("HasSamePCRSelection result is not expected")
		}
	}
}

func TestFormatPCRs_MaxUint32(t *testing.T) {
	pcrs := &pb.PCRs{
		Hash: pb.HashAlgo(tpm2.AlgSHA256),
		Pcrs: map[uint32][]byte{
			math.MaxUint32: []byte{0xaa, 0xbb},
		},
	}
	var buf bytes.Buffer
	if err := FormatPCRs(&buf, pcrs); err != nil {
		t.Fatalf("FormatPCRs failed: %v", err)
	}
	if !strings.Contains(buf.String(), "4294967295: 0xAABB") {
		t.Errorf("FormatPCRs output unexpected: %s", buf.String())
	}
}

func TestPCRSessionAuth_LargePCRIndex(t *testing.T) {
	pcrs := &pb.PCRs{
		Hash: pb.HashAlgo(tpm2.AlgSHA256),
		Pcrs: map[uint32][]byte{
			25: []byte{0x01},
		},
	}
	auth := PCRSessionAuth(pcrs, crypto.SHA256)
	if len(auth) != crypto.SHA256.Size() {
		t.Errorf("got auth length %d, want %d", len(auth), crypto.SHA256.Size())
	}
}

