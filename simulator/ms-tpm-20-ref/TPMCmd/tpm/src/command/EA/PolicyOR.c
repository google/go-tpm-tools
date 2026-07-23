#include "Tpm.h"
#include "PolicyOR_fp.h"

#if CC_PolicyOR  // Conditional expansion of this file

#  include "Policy_spt_fp.h"

/*(See part 3 specification)
// PolicyOR command
*/
//  Return Type: TPM_RC
//      TPM_RC_VALUE            no digest in 'pHashList' matched the current
//                              value of policyDigest for 'policySession'
TPM_RC
TPM2_PolicyOR(PolicyOR_In* in  // IN: input parameter list
)
{
    SESSION* session;
    UINT32   i;

    // Input Validation and Update

    // Get pointer to the session structure
    session = SessionGet(in->policySession);
    pAssert_RC(session);

    // Compare and Update Internal Session policy if match
    for(i = 0; i < in->pHashList.count; i++)
    {
        if(session->attributes.isTrialPolicy == SET
           || (MemoryEqual2B(&session->u2.policyDigest.b,
                             &in->pHashList.digests[i].b)))
        {
            // Found a match
            HASH_STATE hashState;
            TPM_CC     commandCode = TPM_CC_PolicyOR;

            // Start hash
            session->u2.policyDigest.t.size =
                CryptHashStart(&hashState, session->authHashAlg);
            // Set policyDigest to 0 string and add it to hash
            MemorySet(session->u2.policyDigest.t.buffer,
                      0,
                      session->u2.policyDigest.t.size);
            CryptDigestUpdate2B(&hashState, &session->u2.policyDigest.b);

            // add command code
            CryptDigestUpdateInt(&hashState, sizeof(TPM_CC), commandCode);

            // Add each of the hashes in the list
            for(i = 0; i < in->pHashList.count; i++)
            {
                // Extend policyDigest
                CryptDigestUpdate2B(&hashState, &in->pHashList.digests[i].b);
            }
            // Complete digest
            CryptHashEnd2B(&hashState, &session->u2.policyDigest.b);

            return TPM_RC_SUCCESS;
        }
    }
    // None of the values in the list matched the current policyDigest
    return TPM_RCS_VALUE + RC_PolicyOR_pHashList;
}

#endif  // CC_PolicyOR