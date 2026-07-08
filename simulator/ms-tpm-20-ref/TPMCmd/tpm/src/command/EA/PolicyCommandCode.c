#include "Tpm.h"
#include "PolicyCommandCode_fp.h"

#if CC_PolicyCommandCode  // Conditional expansion of this file

/*(See part 3 specification)
// Add a Command Code restriction to the policyDigest
*/
//  Return Type: TPM_RC
//      TPM_RC_VALUE        'commandCode' of 'policySession' previously set to
//                          a different value

TPM_RC
TPM2_PolicyCommandCode(PolicyCommandCode_In* in  // IN: input parameter list
)
{
    SESSION*   session;
    TPM_CC     commandCode = TPM_CC_PolicyCommandCode;
    HASH_STATE hashState;

    // Input validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);
    pAssert_RC(session);

    if(session->commandCode != 0 && session->commandCode != in->code)
        return TPM_RCS_VALUE + RC_PolicyCommandCode_code;
    if(CommandCodeToCommandIndex(in->code) == UNIMPLEMENTED_COMMAND_INDEX)
        return TPM_RCS_POLICY_CC + RC_PolicyCommandCode_code;

    // Internal Data Update
    // Update policy hash
    // policyDigestnew = hash(policyDigestold || TPM_CC_PolicyCommandCode || code)
    //  Start hash
    CryptHashStart(&hashState, session->authHashAlg);

    //  add old digest
    CryptDigestUpdate2B(&hashState, &session->u2.policyDigest.b);

    //  add commandCode
    CryptDigestUpdateInt(&hashState, sizeof(TPM_CC), commandCode);

    //  add input commandCode
    CryptDigestUpdateInt(&hashState, sizeof(TPM_CC), in->code);

    //  complete the hash and get the results
    CryptHashEnd2B(&hashState, &session->u2.policyDigest.b);

    // update commandCode value in session context
    session->commandCode = in->code;

    return TPM_RC_SUCCESS;
}

#endif  // CC_PolicyCommandCode