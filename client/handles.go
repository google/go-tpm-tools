package client

import (
	"fmt"
	"io"
	"math"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// Reserved Handles from "TCG TPM v2.0 Provisioning Guidance" - v1r1 - Table 2
const (
	EKReservedHandle     = tpmutil.Handle(0x81010001)
	EKECCReservedHandle  = tpmutil.Handle(0x81010002)
	SRKReservedHandle    = tpmutil.Handle(0x81000001)
	SRKECCReservedHandle = tpmutil.Handle(0x81000002)
)

// Picked available handles from TPM 2.0 Handles and Localities 2.3.1 - Table 11
// go-tpm-tools will use handles in the range from 0x81008F00 to 0x81008FFF
// DefaultAKECCPrimaryHandle and DefaultAKRSAPrimaryHandle are handles to the
// go-tpm-tools default primary AK ECC and RSA, respectively.
// DefaultAKECCChildHandle and DefaultAKRSAChildHandle are handles to the
// go-tpm-tools default SRK child AK ECC and RSA, respectively.
const (
	DefaultAKECCPrimaryHandle = tpmutil.Handle(0x81008F00)
	DefaultAKRSAPrimaryHandle = tpmutil.Handle(0x81008F01)
	DefaultAKECCChildHandle   = tpmutil.Handle(0x81008F02)
	DefaultAKRSAChildHandle   = tpmutil.Handle(0x81008F03)
)

func isHierarchy(h tpmutil.Handle) bool {
	return h == tpm2.HandleOwner || h == tpm2.HandleEndorsement ||
		h == tpm2.HandlePlatform || h == tpm2.HandleNull
}

// Handles returns a slice of tpmutil.Handle objects of all handles within
// the TPM rw of type handleType.
func Handles(rw io.ReadWriter, handleType tpm2.HandleType) ([]tpmutil.Handle, error) {
	// Handle type is determined by the most-significant octet (MSO) of the property.
	property := uint32(handleType) << 24

	vals, moreData, err := tpm2.GetCapability(rw, tpm2.CapabilityHandles, math.MaxUint32, property)
	if err != nil {
		return nil, err
	}
	if moreData {
		return nil, fmt.Errorf("tpm2.GetCapability() should never return moreData==true for tpm2.CapabilityHandles")
	}
	handles := make([]tpmutil.Handle, len(vals))
	for i, v := range vals {
		handle, ok := v.(tpmutil.Handle)
		if !ok {
			return nil, fmt.Errorf("unable to assert type tpmutil.Handle of value %#v", v)
		}
		handles[i] = handle
	}
	return handles, nil
}
