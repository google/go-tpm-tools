#include "Tpm.h"
#include "PolicyParameters_fp.h"

#if CC_PolicyParameters  // Conditional expansion of this file

/*(See part 3 specification)
// Add a parameters restriction to the policyDigest
*/
//  Return Type: TPM_RC
//      TPM_RC_CPHASH     cpHash of 'policySession' has previously been set
//                        to a different value
//      TPM_RC_SIZE       'pHash' is not the size of the digest produced by the
//                        hash algorithm associated with 'policySession'
TPM_RC
TPM2_PolicyParameters(PolicyParameters_In* in  // IN: input parameter list
)
{
    SESSION*   session;
    TPM_CC     commandCode = TPM_CC_PolicyParameters;
    HASH_STATE hashState;

    // Input Validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    // A valid pHash must have the same size as session hash digest
    // Since the authHashAlg for a session cannot be TPM_ALG_NULL, the digest size
    // is always non-zero.
    if(in->pHash.t.size != CryptHashGetDigestSize(session->authHashAlg))
        return TPM_RCS_SIZE + RC_PolicyParameters_pHash;

    // error if the pHash in session context is not empty
    if(IsCpHashUnionOccupied(session->attributes))
        return TPM_RC_CPHASH;

    // Internal Data Update

    // Update policy hash
    // policyDigestnew = hash(policyDigestold || TPM_CC_PolicyParameters || pHash)
    //  Start hash
    CryptHashStart(&hashState, session->authHashAlg);

    //  add old digest
    CryptDigestUpdate2B(&hashState, &session->u2.policyDigest.b);

    //  add commandCode
    CryptDigestUpdateInt(&hashState, sizeof(TPM_CC), commandCode);

    //  add pHash
    CryptDigestUpdate2B(&hashState, &in->pHash.b);

    //  complete the digest
    CryptHashEnd2B(&hashState, &session->u2.policyDigest.b);

    // update pHash in session context
    session->u1.pHash                           = in->pHash;
    session->attributes.isParametersHashDefined = SET;

    return TPM_RC_SUCCESS;
}

#endif  // CC_PolicyParameters
