package proto

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestHasSamePCRSelection(t *testing.T) {
	var tests = []struct {
		pcrs        *Pcrs
		pcrSel      tpm2.PCRSelection
		expectedRes bool
	}{
		{&Pcrs{}, tpm2.PCRSelection{}, true},
		{&Pcrs{Hash: HashAlgo(tpm2.AlgSHA256), Pcrs: map[uint32][]byte{1: {}}},
			tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{1}}, true},
		{&Pcrs{Hash: HashAlgo(tpm2.AlgSHA256), Pcrs: map[uint32][]byte{}},
			tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{}}, true},
		{&Pcrs{Hash: HashAlgo(tpm2.AlgSHA256), Pcrs: map[uint32][]byte{1: {}}},
			tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{4}}, false},
		{&Pcrs{Hash: HashAlgo(tpm2.AlgSHA256), Pcrs: map[uint32][]byte{1: {}, 4: {}}},
			tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{4}}, false},
		{&Pcrs{Hash: HashAlgo(tpm2.AlgSHA256), Pcrs: map[uint32][]byte{1: {}, 2: {}}},
			tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{1, 2}}, false},
	}
	for _, test := range tests {
		if test.pcrs.HasSamePCRSelection(test.pcrSel) != test.expectedRes {
			t.Errorf("HasSamePCRSelection result is not expected")
		}
	}
}
