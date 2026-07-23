#include "Tpm.h"
#include "PolicyPassword_fp.h"

#if CC_PolicyPassword  // Conditional expansion of this file

#  include "Policy_spt_fp.h"

/*(See part 3 specification)
// allows a policy to be bound to the authorization value of the authorized
// object
*/
TPM_RC
TPM2_PolicyPassword(PolicyPassword_In* in  // IN: input parameter list
)
{
    SESSION*   session;
    TPM_CC     commandCode = TPM_CC_PolicyAuthValue;
    HASH_STATE hashState;

    // Internal Data Update

    // Get pointer to the session structure
    session = SessionGet(in->policySession);
    pAssert_RC(session);

    // Update policy hash
    // policyDigestnew = hash(policyDigestold || TPM_CC_PolicyAuthValue)
    //  Start hash
    CryptHashStart(&hashState, session->authHashAlg);

    //  add old digest
    CryptDigestUpdate2B(&hashState, &session->u2.policyDigest.b);

    //  add commandCode
    CryptDigestUpdateInt(&hashState, sizeof(TPM_CC), commandCode);

    //  complete the digest
    CryptHashEnd2B(&hashState, &session->u2.policyDigest.b);

    //  Update isPasswordNeeded bit
    session->attributes.isPasswordNeeded  = SET;
    session->attributes.isAuthValueNeeded = CLEAR;

    return TPM_RC_SUCCESS;
}

#endif  // CC_PolicyPassword