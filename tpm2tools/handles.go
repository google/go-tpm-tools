package tpm2tools

import (
	"fmt"
	"io"
	"math"

	"github.com/google/go-tpm/tpmutil"
	"github.com/samdamana/go-tpm/tpm2"
)

// FlushActiveHandles calls FlushContext() on all active handles within the
// TPM at io.ReadWriter rw. Returns nil if successful or TPM has no active
// handles.
func FlushActiveHandles(rw io.ReadWriter) error {
	handles, err := Handles(rw, tpm2.HandleTypeTransient)
	if err != nil {
		return err
	}
	for _, handle := range handles {
		err = tpm2.FlushContext(rw, handle)
		if err != nil {
			return err
		}
	}
	return nil
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
		handles[i] = v.(tpmutil.Handle)
	}
	return handles, nil
}
