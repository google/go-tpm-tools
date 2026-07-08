#include "Tpm.h"
#include "NV_ReadLock_fp.h"

#if CC_NV_ReadLock  // Conditional expansion of this file

/*(See part 3 specification)
// Set read lock on a NV index
*/
//  Return Type: TPM_RC
//      TPM_RC_ATTRIBUTES               TPMA_NV_READ_STCLEAR is not SET so
//                                      Index referenced by 'nvIndex' may not be
//                                      write locked
//      TPM_RC_NV_AUTHORIZATION         the authorization was valid but the
//                                      authorizing entity ('authHandle')
//                                      is not allowed to read from the Index
//                                      referenced by 'nvIndex'
TPM_RC
TPM2_NV_ReadLock(NV_ReadLock_In* in  // IN: input parameter list
)
{
    TPM_RC result;
    NV_REF locator;
    // The referenced index has been checked multiple times before this is called
    // so it must be present and will be loaded into cache
    NV_INDEX* nvIndex      = NvGetIndexInfo(in->nvIndex, &locator);
    TPMA_NV   nvAttributes = nvIndex->publicArea.attributes;

    // Input Validation

    // Common Read-Only mode check. May return TPM_RC_READ_ONLY
    result = NvReadOnlyModeChecks(nvIndex->publicArea.attributes);
    if(result != TPM_RC_SUCCESS)
        return result;

    // Common read access checks. NvReadAccessChecks() may return
    // TPM_RC_NV_AUTHORIZATION, TPM_RC_NV_LOCKED, or TPM_RC_NV_UNINITIALIZED
    result = NvReadAccessChecks(in->authHandle, in->nvIndex, nvAttributes);
    if(result == TPM_RC_NV_AUTHORIZATION)
        return TPM_RC_NV_AUTHORIZATION;
    // Index is already locked for write
    else if(result == TPM_RC_NV_LOCKED)
        return TPM_RC_SUCCESS;

    // If NvReadAccessChecks return TPM_RC_NV_UNINITALIZED, then continue.
    // It is not an error to read lock an uninitialized Index.

    // if TPMA_NV_READ_STCLEAR is not set, the index can not be read-locked
    if(!IS_ATTRIBUTE(nvAttributes, TPMA_NV, READ_STCLEAR))
        return TPM_RCS_ATTRIBUTES + RC_NV_ReadLock_nvIndex;

    // Internal Data Update

    // Set the READLOCK attribute
    SET_ATTRIBUTE(nvAttributes, TPMA_NV, READLOCKED);

    // Write NV info back
    return NvWriteIndexAttributes(nvIndex->publicArea.nvIndex, locator, nvAttributes);
}

#endif  // CC_NV_ReadLock