#include "Tpm.h"
#include "PolicyNvWritten_fp.h"

#if CC_PolicyNvWritten  // Conditional expansion of this file

// Make an NV Index policy dependent on the state of the TPMA_NV_WRITTEN
// attribute of the index.
//  Return Type: TPM_RC
//      TPM_RC_VALUE         a conflicting request for the attribute has
//                           already been processed
TPM_RC
TPM2_PolicyNvWritten(PolicyNvWritten_In* in  // IN: input parameter list
)
{
    SESSION*   session;
    TPM_CC     commandCode = TPM_CC_PolicyNvWritten;
    HASH_STATE hashState;

    // Input Validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);
    pAssert_RC(session);

    // If already set is this a duplicate (the same setting)? If it
    // is a conflicting setting, it is an error
    if(session->attributes.checkNvWritten == SET)
    {
        if(((session->attributes.nvWrittenState == SET) != (in->writtenSet == YES)))
            return TPM_RCS_VALUE + RC_PolicyNvWritten_writtenSet;
    }

    // Internal Data Update

    // Set session attributes so that the NV Index needs to be checked
    session->attributes.checkNvWritten = SET;
    session->attributes.nvWrittenState = (in->writtenSet == YES);

    // Update policy hash
    // policyDigestnew = hash(policyDigestold || TPM_CC_PolicyNvWritten
    //                          || writtenSet)
    // Start hash
    CryptHashStart(&hashState, session->authHashAlg);

    // add old digest
    CryptDigestUpdate2B(&hashState, &session->u2.policyDigest.b);

    // add commandCode
    CryptDigestUpdateInt(&hashState, sizeof(TPM_CC), commandCode);

    // add the byte of writtenState
    CryptDigestUpdateInt(&hashState, sizeof(TPMI_YES_NO), in->writtenSet);

    // complete the digest
    CryptHashEnd2B(&hashState, &session->u2.policyDigest.b);

    return TPM_RC_SUCCESS;
}

#endif  // CC_PolicyNvWritten