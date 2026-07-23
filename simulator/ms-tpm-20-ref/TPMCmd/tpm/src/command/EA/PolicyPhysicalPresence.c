#include "Tpm.h"
#include "PolicyPhysicalPresence_fp.h"

#if CC_PolicyPhysicalPresence  // Conditional expansion of this file

/*(See part 3 specification)
// indicate that physical presence will need to be asserted at the time the
// authorization is performed
*/
TPM_RC
TPM2_PolicyPhysicalPresence(PolicyPhysicalPresence_In* in  // IN: input parameter list
)
{
    SESSION*   session;
    TPM_CC     commandCode = TPM_CC_PolicyPhysicalPresence;
    HASH_STATE hashState;

    // Internal Data Update

    // Get pointer to the session structure
    session = SessionGet(in->policySession);
    pAssert_RC(session);

    // Update policy hash
    // policyDigestnew = hash(policyDigestold || TPM_CC_PolicyPhysicalPresence)
    //  Start hash
    CryptHashStart(&hashState, session->authHashAlg);

    //  add old digest
    CryptDigestUpdate2B(&hashState, &session->u2.policyDigest.b);

    //  add commandCode
    CryptDigestUpdateInt(&hashState, sizeof(TPM_CC), commandCode);

    //  complete the digest
    CryptHashEnd2B(&hashState, &session->u2.policyDigest.b);

    // update session attribute
    session->attributes.isPPRequired = SET;

    return TPM_RC_SUCCESS;
}

#endif  // CC_PolicyPhysicalPresence