#include "Tpm.h"

#if CC_PolicyPCR  // Conditional expansion of this file

#  include "PolicyPCR_fp.h"
#  include "Marshal.h"

/*(See part 3 specification)
// Add a PCR gate for a policy session
*/
//  Return Type: TPM_RC
//      TPM_RC_VALUE          if provided, 'pcrDigest' does not match the
//                            current PCR settings
//      TPM_RC_PCR_CHANGED    a previous TPM2_PolicyPCR() set
//                            pcrCounter and it has changed
TPM_RC
TPM2_PolicyPCR(PolicyPCR_In* in  // IN: input parameter list
)
{
    SESSION*     session;
    TPM2B_DIGEST pcrDigest;
    BYTE         pcrs[sizeof(TPML_PCR_SELECTION)];
    UINT32       pcrSize;
    BYTE*        buffer;
    TPM_CC       commandCode = TPM_CC_PolicyPCR;
    HASH_STATE   hashState;

    // Input Validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);
    pAssert_RC(session);

    // Compute current PCR digest
    TPM_RC result =
        PCRComputeCurrentDigest(session->authHashAlg, &in->pcrs, &pcrDigest);
    if(result != TPM_RC_SUCCESS)
        return result;

    // Do validation for non trial session
    if(session->attributes.isTrialPolicy == CLEAR)
    {
        // Make sure that this is not going to invalidate a previous PCR check
        if(session->pcrCounter != 0 && session->pcrCounter != gr.pcrCounter)
            return TPM_RC_PCR_CHANGED;

        // If the caller specified the PCR digest and it does not
        // match the current PCR settings, return an error..
        if(in->pcrDigest.t.size != 0)
        {
            if(!MemoryEqual2B(&in->pcrDigest.b, &pcrDigest.b))
                return TPM_RCS_VALUE + RC_PolicyPCR_pcrDigest;
        }
    }
    else
    {
        // For trial session, just use the input PCR digest if one provided
        // Note: It can't be too big because it is a TPM2B_DIGEST and the size
        // would have been checked during unmarshaling
        if(in->pcrDigest.t.size != 0)
            pcrDigest = in->pcrDigest;
    }
    // Internal Data Update
    // Update policy hash
    // policyDigestnew = hash(   policyDigestold || TPM_CC_PolicyPCR
    //                      || PCRS || pcrDigest)
    //  Start hash
    CryptHashStart(&hashState, session->authHashAlg);

    //  add old digest
    CryptDigestUpdate2B(&hashState, &session->u2.policyDigest.b);

    //  add commandCode
    CryptDigestUpdateInt(&hashState, sizeof(TPM_CC), commandCode);

    //  add PCRS
    buffer  = pcrs;
    pcrSize = TPML_PCR_SELECTION_Marshal(&in->pcrs, &buffer, NULL);
    CryptDigestUpdate(&hashState, pcrSize, pcrs);

    //  add PCR digest
    CryptDigestUpdate2B(&hashState, &pcrDigest.b);

    //  complete the hash and get the results
    CryptHashEnd2B(&hashState, &session->u2.policyDigest.b);

    //  update pcrCounter in session context for non trial session
    if(session->attributes.isTrialPolicy == CLEAR)
    {
        session->pcrCounter = gr.pcrCounter;
    }

    return TPM_RC_SUCCESS;
}

#endif  // CC_PolicyPCR