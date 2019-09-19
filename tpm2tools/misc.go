package tpm2tools

import (
	"io"

	"github.com/google/go-tpm-tools/proto"
	"github.com/google/go-tpm/tpm2"
)

// ReadPCRs fetchs the values of the specified PCRs for the specified hash.
func ReadPCRs(rw io.ReadWriter, pcrs []int, hash tpm2.Algorithm) (*proto.Pcrs, error) {
	pcrSel := tpm2.PCRSelection{
		Hash: hash,
		PCRs: pcrs,
	}

	pcrMap, err := tpm2.ReadPCRs(rw, pcrSel)
	if err != nil {
		return nil, err
	}

	pl := proto.Pcrs{
		Hash: proto.HashAlgo(hash),
		Pcrs: map[uint32][]byte{},
	}

	for pcr, val := range pcrMap {
		pl.Pcrs[uint32(pcr)] = val
	}

	return &pl, nil
}
