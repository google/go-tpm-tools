#include "Tpm.h"
#include "PolicySecret_fp.h"

#if CC_PolicySecret  // Conditional expansion of this file

#  include "Policy_spt_fp.h"
#  include "NV_spt_fp.h"

/*(See part 3 specification)
// Add a secret-based authorization to the policy evaluation
*/
//  Return Type: TPM_RC
//      TPM_RC_CPHASH           cpHash for policy was previously set to a
//                              value that is not the same as 'cpHashA'
//      TPM_RC_EXPIRED          'expiration' indicates a time in the past
//      TPM_RC_NONCE            'nonceTPM' does not match the nonce associated
//                              with 'policySession'
//      TPM_RC_SIZE             'cpHashA' is not the size of a digest for the
//                              hash associated with 'policySession'
TPM_RC
TPM2_PolicySecret(PolicySecret_In*  in,  // IN: input parameter list
                  PolicySecret_Out* out  // OUT: output parameter list
)
{
    TPM_RC     result;
    SESSION*   session;
    TPM2B_NAME entityName;
    UINT64     authTimeout = 0;
    // Input Validation

#  if CC_ReadOnlyControl
    // Don't allow on PIN PASS or PIN FAIL indices when in Read-Only mode
    if(gc.readOnly && NvIsPinCountedIndex(in->authHandle))
        return TPM_RC_READ_ONLY;
#  endif  // CC_ReadOnlyControl

    // Get pointer to the session structure
    session = SessionGet(in->policySession);
    pAssert_RC(session);

    //Only do input validation if this is not a trial policy session
    if(session->attributes.isTrialPolicy == CLEAR)
    {
        authTimeout = ComputeAuthTimeout(session, in->expiration, &in->nonceTPM);

        result      = PolicyParameterChecks(session,
                                       authTimeout,
                                       &in->cpHashA,
                                       &in->nonceTPM,
                                       RC_PolicySecret_nonceTPM,
                                       RC_PolicySecret_cpHashA,
                                       RC_PolicySecret_expiration);
        if(result != TPM_RC_SUCCESS)
            return result;
    }
    // Internal Data Update
    // Update policy context with input policyRef and name of authorizing key
    // This value is computed even for trial sessions. Possibly update the cpHash
    result = PolicyContextUpdate(TPM_CC_PolicySecret,
                                 EntityGetName(in->authHandle, &entityName),
                                 &in->policyRef,
                                 &in->cpHashA,
                                 authTimeout,
                                 session);
    if(result != TPM_RC_SUCCESS)
    {
        return result;
    }

    // Command Output
    // Create ticket and timeout buffer if in->expiration < 0 and this is not
    // a trial session.
    // NOTE: PolicyParameterChecks() makes sure that nonceTPM is present
    // when expiration is non-zero.
    if(in->expiration < 0 && session->attributes.isTrialPolicy == CLEAR
       && !NvIsPinPassIndex(in->authHandle))
    {
        BOOL expiresOnReset = (in->nonceTPM.t.size == 0);
        // Compute policy ticket
        authTimeout &= ~EXPIRATION_BIT;
        result = TicketComputeAuth(TPM_ST_AUTH_SECRET,
                                   EntityGetHierarchy(in->authHandle),
                                   authTimeout,
                                   expiresOnReset,
                                   &in->cpHashA,
                                   &in->policyRef,
                                   &entityName,
                                   &out->policyTicket);
        if(result != TPM_RC_SUCCESS)
            return result;

        // Generate timeout buffer.  The format of output timeout buffer is
        // TPM-specific.
        // Note: In this implementation, the timeout buffer value is computed after
        // the ticket is produced so, when the ticket is checked, the expiration
        // flag needs to be extracted before the ticket is checked.
        out->timeout.t.size = sizeof(authTimeout);
        // In the Windows compatible version, the least-significant bit of the
        // timeout value is used as a flag to indicate if the authorization expires
        // on reset. The flag is the MSb.
        if(expiresOnReset)
            authTimeout |= EXPIRATION_BIT;
        UINT64_TO_BYTE_ARRAY(authTimeout, out->timeout.t.buffer);
    }
    else
    {
        // timeout buffer is null
        out->timeout.t.size = 0;

        // authorization ticket is null
        out->policyTicket.tag           = TPM_ST_AUTH_SECRET;
        out->policyTicket.hierarchy     = TPM_RH_NULL;
        out->policyTicket.digest.t.size = 0;
    }
    return result;
}

#endif  // CC_PolicySecret