package tpm2tools


import (
    "io"
    "github.com/google/go-tpm/tpm2"
    "github.com/google/go-tpm/tpmutil"
)

// FlushActiveHandles calls FlushContext() on all active handles within the 
// TPM at io.ReadWriter rw. Returns nil if successful or TPM has no active
// handles.
func FlushActiveHandles(rw io.ReadWriter) error {
    handles, err := activeHandles(rw)
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

// activeHandles returns a slice of tpmutil.Handle objects of all handles
// active within the TPM at ioReadWriter rw.
func activeHandles(rw io.ReadWriter) ([]tpmutil.Handle, error) {
    vals, _, err := tpm2.GetCapability(rw, tpm2.CapabilityHandles, ^uint32(0), 0x80000000)
    if err != nil {
        return nil, err
    }
    handles := make([]tpmutil.Handle, len(vals))
    for i, v := range vals {
        handles[i] = v.(tpmutil.Handle)
    }
    return handles, nil
}

