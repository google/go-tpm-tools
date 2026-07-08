#include "Tpm.h"
#include "FlushContext_fp.h"

#if CC_FlushContext  // Conditional expansion of this file

/*(See part 3 specification)
// Flush a specific object or session
*/
//  Return Type: TPM_RC
//      TPM_RC_HANDLE      'flushHandle' does not reference a loaded object or session
TPM_RC
TPM2_FlushContext(FlushContext_In* in  // IN: input parameter list
)
{
    // Internal Data Update

    // Call object or session specific routine to flush
    switch(HandleGetType(in->flushHandle))
    {
        case TPM_HT_TRANSIENT:
            if(!IsObjectPresent(in->flushHandle))
                return TPM_RCS_HANDLE + RC_FlushContext_flushHandle;
            // Flush object
            if(!FlushObject(in->flushHandle))
                return TPM_RC_FAILURE;
            break;
        case TPM_HT_HMAC_SESSION:
        case TPM_HT_POLICY_SESSION:
            if(!SessionIsLoaded(in->flushHandle) && !SessionIsSaved(in->flushHandle))
                return TPM_RCS_HANDLE + RC_FlushContext_flushHandle;

            // If the session to be flushed is the exclusive audit session, then
            // indicate that there is no exclusive audit session any longer.
            if(in->flushHandle == g_exclusiveAuditSession)
                g_exclusiveAuditSession = TPM_RH_UNASSIGNED;

            // Flush session
            SessionFlush(in->flushHandle);
            VERIFY_NOT_FAILED();
            break;
        default:
            // This command only takes object or session handle.  Other handles
            // should be filtered out at handle unmarshal
            FAIL(FATAL_ERROR_INTERNAL);
            break;
    }

    return TPM_RC_SUCCESS;
}

#endif  // CC_FlushContext