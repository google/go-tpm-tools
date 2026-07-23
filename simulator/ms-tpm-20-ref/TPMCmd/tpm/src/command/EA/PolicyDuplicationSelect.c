#include "Tpm.h"
#include "PolicyDuplicationSelect_fp.h"

#if CC_PolicyDuplicationSelect  // Conditional expansion of this file

/*(See part 3 specification)
// allows qualification of duplication so that it a specific new parent may be
// selected or a new parent selected for a specific object.
*/
//  Return Type: TPM_RC
//      TPM_RC_COMMAND_CODE   'commandCode' of 'policySession' is not empty
//      TPM_RC_CPHASH         'nameHash' of 'policySession' is not empty
TPM_RC
TPM2_PolicyDuplicationSelect(
    PolicyDuplicationSelect_In* in  // IN: input parameter list
)
{
    SESSION*   session;
    HASH_STATE hashState;
    TPM_CC     commandCode = TPM_CC_PolicyDuplicationSelect;

    // Input Validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);
    pAssert_RC(session);

    // nameHash in session context must be empty
    if(session->u1.nameHash.t.size != 0)
        return TPM_RC_CPHASH;

    // commandCode in session context must be empty
    if(session->commandCode != 0)
        return TPM_RC_COMMAND_CODE;

    // Internal Data Update

    // Update name hash
    session->u1.nameHash.t.size = CryptHashStart(&hashState, session->authHashAlg);

    //  add objectName
    CryptDigestUpdate2B(&hashState, &in->objectName.b);

    //  add new parent name
    CryptDigestUpdate2B(&hashState, &in->newParentName.b);

    //  complete hash
    CryptHashEnd2B(&hashState, &session->u1.nameHash.b);
    session->attributes.isNameHashDefined = SET;

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

    //  add new parent name
    CryptDigestUpdate2B(&hashState, &in->newParentName.b);

    //  add includeObject
    CryptDigestUpdateInt(&hashState, sizeof(TPMI_YES_NO), in->includeObject);

    //  complete digest
    CryptHashEnd2B(&hashState, &session->u2.policyDigest.b);

    // set commandCode in session context
    session->commandCode = TPM_CC_Duplicate;

    return TPM_RC_SUCCESS;
}

#endif  // CC_PolicyDuplicationSelect