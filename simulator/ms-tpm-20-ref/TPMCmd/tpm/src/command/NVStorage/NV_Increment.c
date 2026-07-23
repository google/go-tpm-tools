#include "Tpm.h"
#include "NV_Increment_fp.h"

#if CC_NV_Increment  // Conditional expansion of this file

/*(See part 3 specification)
// Increment a NV counter
*/
//  Return Type: TPM_RC
//      TPM_RC_ATTRIBUTES               NV index is not a counter
//      TPM_RC_NV_AUTHORIZATION         authorization failure
//      TPM_RC_NV_LOCKED                Index is write locked
TPM_RC
TPM2_NV_Increment(NV_Increment_In* in  // IN: input parameter list
)
{
    TPM_RC    result;
    NV_REF    locator;
    NV_INDEX* nvIndex = NvGetIndexInfo(in->nvIndex, &locator);
    UINT64    countValue;

    // Input Validation

    // Common access checks, NvWriteAccessCheck() may return TPM_RC_NV_AUTHORIZATION
    // or TPM_RC_NV_LOCKED
    result = NvWriteAccessChecks(
        in->authHandle, in->nvIndex, nvIndex->publicArea.attributes);
    if(result != TPM_RC_SUCCESS)
        return result;

    // Make sure that this is a counter
    if(!IsNvCounterIndex(nvIndex->publicArea.attributes))
        return TPM_RCS_ATTRIBUTES + RC_NV_Increment_nvIndex;

    // Internal Data Update

    // If counter index is not been written, initialize it
    if(!IS_ATTRIBUTE(nvIndex->publicArea.attributes, TPMA_NV, WRITTEN))
        countValue = NvReadMaxCount();
    else
        // Read NV data in native format for TPM CPU.
        countValue = NvGetUINT64Data(nvIndex, locator);

    // Do the increment
    countValue++;

    // Write NV data back. A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may
    // be returned at this point. If necessary, this function will set the
    // TPMA_NV_WRITTEN attribute
    result = NvWriteUINT64Data(nvIndex, countValue);
    if(result == TPM_RC_SUCCESS)
    {
        // If a counter just rolled over, then force the NV update.
        // Note, if this is an orderly counter, then the write-back needs to be
        // forced, for other counters, the write-back will happen anyway
        if(IS_ATTRIBUTE(nvIndex->publicArea.attributes, TPMA_NV, ORDERLY)
           && (countValue & MAX_ORDERLY_COUNT) == 0)
        {
            // Need to force an NV update of orderly data
            SET_NV_UPDATE(UT_ORDERLY);
        }
    }
    return result;
}

#endif  // CC_NV_Increment