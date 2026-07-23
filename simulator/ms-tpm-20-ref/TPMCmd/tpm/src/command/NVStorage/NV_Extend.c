#include "Tpm.h"
#include "NV_Extend_fp.h"

#if CC_NV_Extend  // Conditional expansion of this file

/*(See part 3 specification)
// Write to a NV index
*/
//  Return Type: TPM_RC
//      TPM_RC_ATTRIBUTES               the TPMA_NV_EXTEND attribute is not SET in
//                                      the Index referenced by 'nvIndex'
//      TPM_RC_NV_AUTHORIZATION         the authorization was valid but the
//                                      authorizing entity ('authHandle')
//                                      is not allowed to write to the Index
//                                      referenced by 'nvIndex'
//      TPM_RC_NV_LOCKED                the Index referenced by 'nvIndex' is locked
//                                      for writing
TPM_RC
TPM2_NV_Extend(NV_Extend_In* in  // IN: input parameter list
)
{
    TPM_RC       result;
    NV_REF       locator;
    NV_INDEX*    nvIndex = NvGetIndexInfo(in->nvIndex, &locator);

    TPM2B_DIGEST oldDigest;
    TPM2B_DIGEST newDigest;
    HASH_STATE   hashState;

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

    // Make sure that this is an extend index
    if(!IsNvExtendIndex(nvIndex->publicArea.attributes))
        return TPM_RCS_ATTRIBUTES + RC_NV_Extend_nvIndex;

    // Internal Data Update

    // Perform the write.
    oldDigest.t.size = CryptHashGetDigestSize(nvIndex->publicArea.nameAlg);
    pAssert_RC(oldDigest.t.size <= sizeof(oldDigest.t.buffer));
    if(IS_ATTRIBUTE(nvIndex->publicArea.attributes, TPMA_NV, WRITTEN))
    {
        NvGetIndexData(nvIndex, locator, 0, oldDigest.t.size, oldDigest.t.buffer);
    }
    else
    {
        MemorySet(oldDigest.t.buffer, 0, oldDigest.t.size);
    }
    // Start hash
    newDigest.t.size = CryptHashStart(&hashState, nvIndex->publicArea.nameAlg);

    // Adding old digest
    CryptDigestUpdate2B(&hashState, &oldDigest.b);

    // Adding new data
    CryptDigestUpdate2B(&hashState, &in->data.b);

    // Complete hash
    CryptHashEnd2B(&hashState, &newDigest.b);

    // Write extended hash back.
    // Note, this routine will SET the TPMA_NV_WRITTEN attribute if necessary
    return NvWriteIndexData(nvIndex, 0, newDigest.t.size, newDigest.t.buffer);
}

#endif  // CC_NV_Extend