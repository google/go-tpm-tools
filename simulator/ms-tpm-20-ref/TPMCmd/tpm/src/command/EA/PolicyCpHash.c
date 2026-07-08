#include "Tpm.h"
#include "PolicyCpHash_fp.h"

#if CC_PolicyCpHash  // Conditional expansion of this file

/*(See part 3 specification)
// Add a cpHash restriction to the policyDigest
*/
//  Return Type: TPM_RC
//      TPM_RC_CPHASH           cpHash of 'policySession' has previously been set
//                              to a different value
//      TPM_RC_SIZE             'cpHashA' is not the size of a digest produced
//                              by the hash algorithm associated with
//                              'policySession'
TPM_RC
TPM2_PolicyCpHash(PolicyCpHash_In* in  // IN: input parameter list
)
{
    SESSION*   session;
    TPM_CC     commandCode = TPM_CC_PolicyCpHash;
    HASH_STATE hashState;

    // Input Validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);
    pAssert_RC(session);

    // A valid cpHash must have the same size as session hash digest
    // NOTE: the size of the digest can't be zero because TPM_ALG_NULL
    // can't be used for the authHashAlg.
    if(in->cpHashA.t.size != CryptHashGetDigestSize(session->authHashAlg))
        return TPM_RCS_SIZE + RC_PolicyCpHash_cpHashA;

    // error if the cpHash in session context is not empty and is not the same
    // as the input or is not a cpHash
    if((IsCpHashUnionOccupied(session->attributes))
       && (!session->attributes.isCpHashDefined
           || !MemoryEqual2B(&in->cpHashA.b, &session->u1.cpHash.b)))
        return TPM_RC_CPHASH;

    // Internal Data Update

    // Update policy hash
    // policyDigestnew = hash(policyDigestold || TPM_CC_PolicyCpHash || cpHashA)
    //  Start hash
    CryptHashStart(&hashState, session->authHashAlg);

    //  add old digest
    CryptDigestUpdate2B(&hashState, &session->u2.policyDigest.b);

    //  add commandCode
    CryptDigestUpdateInt(&hashState, sizeof(TPM_CC), commandCode);

    //  add cpHashA
    CryptDigestUpdate2B(&hashState, &in->cpHashA.b);

    //  complete the digest and get the results
    CryptHashEnd2B(&hashState, &session->u2.policyDigest.b);

    // update cpHash in session context
    session->u1.cpHash                  = in->cpHashA;
    session->attributes.isCpHashDefined = SET;

    return TPM_RC_SUCCESS;
}

#endif  // CC_PolicyCpHash