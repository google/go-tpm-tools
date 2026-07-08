#include "Tpm.h"
#include "NV_SetBits_fp.h"

#if CC_NV_SetBits  // Conditional expansion of this file

/*(See part 3 specification)
// Set bits in a NV index
*/
//  Return Type: TPM_RC
//      TPM_RC_ATTRIBUTES               the TPMA_NV_BITS attribute is not SET in the
//                                      Index referenced by 'nvIndex'
//      TPM_RC_NV_AUTHORIZATION         the authorization was valid but the
//                                      authorizing entity ('authHandle')
//                                      is not allowed to write to the Index
//                                      referenced by 'nvIndex'
//      TPM_RC_NV_LOCKED                the Index referenced by 'nvIndex' is locked
//                                      for writing
TPM_RC
TPM2_NV_SetBits(NV_SetBits_In* in  // IN: input parameter list
)
{
    TPM_RC    result;
    NV_REF    locator;
    NV_INDEX* nvIndex = NvGetIndexInfo(in->nvIndex, &locator);
    UINT64    oldValue;
    UINT64    newValue;

    // Input Validation

    // Common Read-Only mode check. May return TPM_RC_READ_ONLY
    result = NvReadOnlyModeChecks(nvIndex->publicArea.attributes);
    if(result != TPM_RC_SUCCESS)
        return result;

    // Common access checks, NvWriteAccessCheck() may return TPM_RC_NV_AUTHORIZATION
    // or TPM_RC_NV_LOCKED
    result = NvWriteAccessChecks(
        in->authHandle, in->nvIndex, nvIndex->publicArea.attributes);
    if(result != TPM_RC_SUCCESS)
        return result;

    // Make sure that this is a bit field
    if(!IsNvBitsIndex(nvIndex->publicArea.attributes))
        return TPM_RCS_ATTRIBUTES + RC_NV_SetBits_nvIndex;

    // If index is not been written, initialize it
    if(!IS_ATTRIBUTE(nvIndex->publicArea.attributes, TPMA_NV, WRITTEN))
        oldValue = 0;
    else
        // Read index data
        oldValue = NvGetUINT64Data(nvIndex, locator);

    // Figure out what the new value is going to be
    newValue = oldValue | in->bits;

    // Internal Data Update
    return NvWriteUINT64Data(nvIndex, newValue);
}

#endif  // CC_NV_SetBits