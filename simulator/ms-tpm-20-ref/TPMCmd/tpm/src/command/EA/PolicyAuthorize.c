#include "Tpm.h"
#include "PolicyAuthorize_fp.h"

#if CC_PolicyAuthorize  // Conditional expansion of this file

#  include "Policy_spt_fp.h"

/*(See part 3 specification)
// Change policy by a signature from authority
*/
//  Return Type: TPM_RC
//      TPM_RC_HASH         hash algorithm in 'keyName' is not supported
//      TPM_RC_SIZE         'keyName' is not the correct size for its hash algorithm
//      TPM_RC_VALUE        the current policyDigest of 'policySession' does not
//                          match 'approvedPolicy'; or 'checkTicket' doesn't match
//                          the provided values
TPM_RC
TPM2_PolicyAuthorize(PolicyAuthorize_In* in  // IN: input parameter list
)
{
    TPM_RC           result = TPM_RC_SUCCESS;
    SESSION*         session;
    TPM2B_DIGEST     authHash;
    HASH_STATE       hashState;
    TPMT_TK_VERIFIED ticket;
    TPM_ALG_ID       hashAlg;
    UINT16           digestSize;

    // Input Validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);
    pAssert_RC(session);

    if(in->keySign.t.size < 2)
    {
        return TPM_RCS_SIZE + RC_PolicyAuthorize_keySign;
    }

    // Extract from the Name of the key, the algorithm used to compute its Name
    hashAlg = BYTE_ARRAY_TO_UINT16(in->keySign.t.name);

    // 'keySign' parameter needs to use a supported hash algorithm, otherwise
    // can't tell how large the digest should be
    if(!CryptHashIsValidAlg(hashAlg, FALSE))
        return TPM_RCS_HASH + RC_PolicyAuthorize_keySign;

    digestSize = CryptHashGetDigestSize(hashAlg);
    if(digestSize != (in->keySign.t.size - 2))
        return TPM_RCS_SIZE + RC_PolicyAuthorize_keySign;

    //If this is a trial policy, skip all validations
    if(session->attributes.isTrialPolicy == CLEAR)
    {
        // Check that "approvedPolicy" matches the current value of the
        // policyDigest in policy session
        if(!MemoryEqual2B(&session->u2.policyDigest.b, &in->approvedPolicy.b))
            return TPM_RCS_VALUE + RC_PolicyAuthorize_approvedPolicy;

        // Validate ticket TPMT_TK_VERIFIED
        // Compute aHash.  The authorizing object sign a digest
        //  aHash := hash(approvedPolicy || policyRef).
        // Start hash
        authHash.t.size = CryptHashStart(&hashState, hashAlg);

        // add approvedPolicy
        CryptDigestUpdate2B(&hashState, &in->approvedPolicy.b);

        // add policyRef
        CryptDigestUpdate2B(&hashState, &in->policyRef.b);

        // complete hash
        CryptHashEnd2B(&hashState, &authHash.b);

        // re-compute TPMT_TK_VERIFIED
        result = TicketComputeVerified(
            in->checkTicket.hierarchy, &authHash, &in->keySign, &ticket);
        if(result != TPM_RC_SUCCESS)
            return result;

        // Compare ticket digest.  If not match, return error
        if(!MemoryEqual2B(&in->checkTicket.digest.b, &ticket.digest.b))
            return TPM_RCS_VALUE + RC_PolicyAuthorize_checkTicket;
    }

    // Internal Data Update

    // Set policyDigest to zero digest
    PolicyDigestClear(session);

    // Update policyDigest
    return PolicyContextUpdate(
        TPM_CC_PolicyAuthorize, &in->keySign, &in->policyRef, NULL, 0, session);
}

#endif  // CC_PolicyAuthorize
