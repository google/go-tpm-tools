#include "Tpm.h"
#include "PolicyNV_fp.h"

#if CC_PolicyNV  // Conditional expansion of this file

#  include "Policy_spt_fp.h"

/*(See part 3 specification)
// Do comparison to NV location
*/
//  Return Type: TPM_RC
//      TPM_RC_AUTH_TYPE            NV index authorization type is not correct
//      TPM_RC_NV_LOCKED            NV index read locked
//      TPM_RC_NV_UNINITIALIZED     the NV index has not been initialized
//      TPM_RC_POLICY               the comparison to the NV contents failed
//      TPM_RC_SIZE                 the size of 'nvIndex' data starting at 'offset'
//                                  is less than the size of 'operandB'
//      TPM_RC_VALUE                'offset' is too large
TPM_RC
TPM2_PolicyNV(PolicyNV_In* in  // IN: input parameter list
)
{
    TPM_RC       result;
    SESSION*     session;
    NV_REF       locator;
    NV_INDEX*    nvIndex;
    BYTE         nvBuffer[sizeof(in->operandB.t.buffer)];
    TPM2B_NAME   nvName;
    TPM_CC       commandCode = TPM_CC_PolicyNV;
    HASH_STATE   hashState;
    TPM2B_DIGEST argHash;

    // Input Validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);
    pAssert_RC(session);

    //If this is a trial policy, skip all validations and the operation
    if(session->attributes.isTrialPolicy == CLEAR)
    {
        // No need to access the actual NV index information for a trial policy.
        nvIndex = NvGetIndexInfo(in->nvIndex, &locator);

        // Common read access checks. NvReadAccessChecks() may return
        // TPM_RC_NV_AUTHORIZATION, TPM_RC_NV_LOCKED, or TPM_RC_NV_UNINITIALIZED
        result = NvReadAccessChecks(
            in->authHandle, in->nvIndex, nvIndex->publicArea.attributes);
        if(result != TPM_RC_SUCCESS)
            return result;

        // Make sure that offset is within range
        if(in->offset > nvIndex->publicArea.dataSize)
            return TPM_RCS_VALUE + RC_PolicyNV_offset;

        // Valid NV data size should not be smaller than input operandB size
        if((nvIndex->publicArea.dataSize - in->offset) < in->operandB.t.size)
            return TPM_RCS_SIZE + RC_PolicyNV_operandB;

        // Get NV data.  The size of NV data equals the input operand B size
        NvGetIndexData(nvIndex, locator, in->offset, in->operandB.t.size, nvBuffer);

        // Check to see if the condition is valid
        if(!PolicySptCheckCondition(
               in->operation, nvBuffer, in->operandB.t.buffer, in->operandB.t.size))
            return TPM_RC_POLICY;
    }
    // Internal Data Update

    // Start argument hash
    argHash.t.size = CryptHashStart(&hashState, session->authHashAlg);

    //  add operandB
    CryptDigestUpdate2B(&hashState, &in->operandB.b);

    //  add offset
    CryptDigestUpdateInt(&hashState, sizeof(UINT16), in->offset);

    //  add operation
    CryptDigestUpdateInt(&hashState, sizeof(TPM_EO), in->operation);

    //  complete argument digest
    CryptHashEnd2B(&hashState, &argHash.b);

    // Update policyDigest
    //  Start digest
    CryptHashStart(&hashState, session->authHashAlg);

    //  add old digest
    CryptDigestUpdate2B(&hashState, &session->u2.policyDigest.b);

    //  add commandCode
    CryptDigestUpdateInt(&hashState, sizeof(TPM_CC), commandCode);

    //  add argument digest
    CryptDigestUpdate2B(&hashState, &argHash.b);

    // Adding nvName
    CryptDigestUpdate2B(&hashState, &EntityGetName(in->nvIndex, &nvName)->b);

    // complete the digest
    CryptHashEnd2B(&hashState, &session->u2.policyDigest.b);

    return TPM_RC_SUCCESS;
}

#endif  // CC_PolicyNV