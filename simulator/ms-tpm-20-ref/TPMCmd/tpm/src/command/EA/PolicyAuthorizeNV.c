#include "Tpm.h"

#if CC_PolicyAuthorizeNV  // Conditional expansion of this file

#  include "PolicyAuthorizeNV_fp.h"
#  include "Policy_spt_fp.h"
#  include "Marshal.h"

/*(See part 3 specification)
// Change policy by a signature from authority
*/
//  Return Type: TPM_RC
//      TPM_RC_HASH         hash algorithm in 'keyName' is not supported or is not
//                          the same as the hash algorithm of the policy session
//      TPM_RC_SIZE         'keyName' is not the correct size for its hash algorithm
//      TPM_RC_VALUE        the current policyDigest of 'policySession' does not
//                          match 'approvedPolicy'; or 'checkTicket' doesn't match
//                          the provided values
TPM_RC
TPM2_PolicyAuthorizeNV(PolicyAuthorizeNV_In* in)
{
    SESSION*   session;
    TPM_RC     result;
    NV_REF     locator;
    NV_INDEX*  nvIndex = NvGetIndexInfo(in->nvIndex, &locator);
    TPM2B_NAME name;
    TPMT_HA    policyInNv;
    BYTE       nvTemp[sizeof(TPMT_HA)];
    BYTE*      buffer = nvTemp;
    INT32      size;

    // Input Validation
    // Get pointer to the session structure
    session = SessionGet(in->policySession);
    pAssert_RC(session);

    // Skip checks if this is a trial policy
    if(!session->attributes.isTrialPolicy)
    {
        // Check the authorizations for reading
        // Common read access checks. NvReadAccessChecks() returns
        // TPM_RC_NV_AUTHORIZATION, TPM_RC_NV_LOCKED, or TPM_RC_NV_UNINITIALIZED
        // error may be returned at this point
        result = NvReadAccessChecks(
            in->authHandle, in->nvIndex, nvIndex->publicArea.attributes);
        if(result != TPM_RC_SUCCESS)
            return result;

        // Read the contents of the index into a temp buffer
        size = MIN(nvIndex->publicArea.dataSize, sizeof(TPMT_HA));
        NvGetIndexData(nvIndex, locator, 0, (UINT16)size, nvTemp);

        // Unmarshal the contents of the buffer into the internal format of a
        // TPMT_HA so that the hash and digest elements can be accessed from the
        // structure rather than the byte array that is in the Index (written by
        // user of the Index).
        result = TPMT_HA_Unmarshal(&policyInNv, &buffer, &size, FALSE);
        if(result != TPM_RC_SUCCESS)
            return result;

        // Verify that the hash is the same
        if(policyInNv.hashAlg != session->authHashAlg)
            return TPM_RC_HASH;

        // See if the contents of the digest in the Index matches the value
        // in the policy
        if(!MemoryEqual(&policyInNv.digest,
                        &session->u2.policyDigest.t.buffer,
                        session->u2.policyDigest.t.size))
            return TPM_RC_VALUE;
    }

    // Internal Data Update

    // Set policyDigest to zero digest
    PolicyDigestClear(session);

    // Update policyDigest
    return PolicyContextUpdate(TPM_CC_PolicyAuthorizeNV,
                               EntityGetName(in->nvIndex, &name),
                               NULL,
                               NULL,
                               0,
                               session);
}

#endif  // CC_PolicyAuthorize