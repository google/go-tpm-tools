package tpm2tools

import (
	"fmt"
	"io"

	"github.com/google/go-tpm-tools/proto"
	"github.com/google/go-tpm/tpm2"
)

// GetPCRCount asks the tpm how many PCRs it has.
func GetPCRCount(rw io.ReadWriter) (uint32, error) {
	props, _, err := tpm2.GetCapability(rw, tpm2.CapabilityTPMProperties, 1, uint32(tpm2.PCRCount))
	if err != nil {
		return 0, err
	}

	if len(props) != 1 {
		return 0, fmt.Errorf("tpm returned unexpected list of properties: %v", props)
	}
	return props[0].(tpm2.TaggedProperty).Value, nil
}

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
