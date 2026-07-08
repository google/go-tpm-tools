#include "Tpm.h"
#include "Policy_AC_SendSelect_fp.h"

#if CC_Policy_AC_SendSelect  // Conditional expansion of this file

/*(See part 3 specification)
// allows qualification of attached component and object to be sent.
*/
//  Return Type: TPM_RC
//      TPM_RC_COMMAND_CODE   'commandCode' of 'policySession' is not empty
//      TPM_RC_CPHASH         'cpHash' of 'policySession' is not empty
TPM_RC
TPM2_Policy_AC_SendSelect(Policy_AC_SendSelect_In* in  // IN: input parameter list
)
{
    SESSION*   session;
    HASH_STATE hashState;
    TPM_CC     commandCode = TPM_CC_Policy_AC_SendSelect;

    // Input Validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);
    pAssert_RC(session);

    // cpHash in session context must be empty
    if(session->u1.cpHash.t.size != 0)
        return TPM_RC_CPHASH;
    // commandCode in session context must be empty
    if(session->commandCode != 0)
        return TPM_RC_COMMAND_CODE;
    // Internal Data Update
    // Update name hash
    session->u1.cpHash.t.size = CryptHashStart(&hashState, session->authHashAlg);

    //  add objectName
    CryptDigestUpdate2B(&hashState, &in->objectName.b);

    // add authHandleName
    CryptDigestUpdate2B(&hashState, &in->authHandleName.b);

    //  add ac name
    CryptDigestUpdate2B(&hashState, &in->acName.b);

    //  complete hash
    CryptHashEnd2B(&hashState, &session->u1.cpHash.b);

    // update policy hash
    // Old policyDigest size should be the same as the new policyDigest size since
    // they are using the same hash algorithm
    session->u2.policyDigest.t.size =
        CryptHashStart(&hashState, session->authHashAlg);
    //  add old policy
    CryptDigestUpdate2B(&hashState, &session->u2.policyDigest.b);

    //  add command code
    CryptDigestUpdateInt(&hashState, sizeof(TPM_CC), commandCode);

    //  add objectName
    if(in->includeObject == YES)
        CryptDigestUpdate2B(&hashState, &in->objectName.b);

    //  add authHandleName
    CryptDigestUpdate2B(&hashState, &in->authHandleName.b);

    // add acName
    CryptDigestUpdate2B(&hashState, &in->acName.b);

    //  add includeObject
    CryptDigestUpdateInt(&hashState, sizeof(TPMI_YES_NO), in->includeObject);

    //  complete digest
    CryptHashEnd2B(&hashState, &session->u2.policyDigest.b);

    // set commandCode in session context
    session->commandCode = TPM_CC_AC_Send;

    return TPM_RC_SUCCESS;
}

#endif  // CC_Policy_AC_SendSelect