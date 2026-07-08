#include "Tpm.h"
#include "NV_WriteLock_fp.h"

#if CC_NV_WriteLock  // Conditional expansion of this file

/*(See part 3 specification)
// Set write lock on a NV index
*/
//  Return Type: TPM_RC
//      TPM_RC_ATTRIBUTES               neither TPMA_NV_WRITEDEFINE nor
//                                      TPMA_NV_WRITE_STCLEAR is SET in Index
//                                      referenced by 'nvIndex'
//      TPM_RC_NV_AUTHORIZATION         the authorization was valid but the
//                                      authorizing entity ('authHandle')
//                                      is not allowed to write to the Index
//                                      referenced by 'nvIndex'
//
TPM_RC
TPM2_NV_WriteLock(NV_WriteLock_In* in  // IN: input parameter list
)
{
    TPM_RC    result;
    NV_REF    locator;
    NV_INDEX* nvIndex      = NvGetIndexInfo(in->nvIndex, &locator);
    TPMA_NV   nvAttributes = nvIndex->publicArea.attributes;

    // Input Validation:

    // Common Read-Only mode check. May return TPM_RC_READ_ONLY
    result = NvReadOnlyModeChecks(nvIndex->publicArea.attributes);
    if(result != TPM_RC_SUCCESS)
        return result;

    // Common access checks, NvWriteAccessCheck() may return TPM_RC_NV_AUTHORIZATION
    // or TPM_RC_NV_LOCKED
    result = NvWriteAccessChecks(in->authHandle, in->nvIndex, nvAttributes);
    if(result != TPM_RC_SUCCESS)
    {
        if(result == TPM_RC_NV_AUTHORIZATION)
            return result;
        // If write access failed because the index is already locked, then it is
        // no error.
        return TPM_RC_SUCCESS;
    }
    // if neither TPMA_NV_WRITEDEFINE nor TPMA_NV_WRITE_STCLEAR is set, the index
    // can not be write-locked
    if(!IS_ATTRIBUTE(nvAttributes, TPMA_NV, WRITEDEFINE)
       && !IS_ATTRIBUTE(nvAttributes, TPMA_NV, WRITE_STCLEAR))
        return TPM_RCS_ATTRIBUTES + RC_NV_WriteLock_nvIndex;
    // Internal Data Update
    // Set the WRITELOCK attribute.
    // Note: if TPMA_NV_WRITELOCKED were already SET, then the write access check
    // above would have failed and this code isn't executed.
    SET_ATTRIBUTE(nvAttributes, TPMA_NV, WRITELOCKED);

    // Write index info back
    return NvWriteIndexAttributes(nvIndex->publicArea.nvIndex, locator, nvAttributes);
}

#endif  // CC_NV_WriteLock