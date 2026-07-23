#include "Tpm.h"
#include "HierarchyChangeAuth_fp.h"

#if CC_HierarchyChangeAuth  // Conditional expansion of this file

#  include "Object_spt_fp.h"

/*(See part 3 specification)
// Set a hierarchy authValue
*/
//  Return Type: TPM_RC
//      TPM_RC_SIZE        'newAuth' size is greater than that of integrity hash
//                          digest
TPM_RC
TPM2_HierarchyChangeAuth(HierarchyChangeAuth_In* in  // IN: input parameter list
)
{
    // The command needs NV update.
    RETURN_IF_NV_IS_NOT_AVAILABLE;

    // Make sure that the authorization value is a reasonable size (not larger than
    // the size of the digest produced by the integrity hash. The integrity
    // hash is assumed to produce the longest digest of any hash implemented
    // on the TPM. This will also remove trailing zeros from the authValue.
    if(MemoryRemoveTrailingZeros(&in->newAuth) > CONTEXT_INTEGRITY_HASH_SIZE)
        return TPM_RCS_SIZE + RC_HierarchyChangeAuth_newAuth;

    // Set hierarchy authValue
    switch(in->authHandle)
    {
        case TPM_RH_OWNER:
            gp.ownerAuth = in->newAuth;
            NV_SYNC_PERSISTENT(ownerAuth);
            break;
        case TPM_RH_ENDORSEMENT:
            gp.endorsementAuth = in->newAuth;
            NV_SYNC_PERSISTENT(endorsementAuth);
            break;
        case TPM_RH_PLATFORM:
            gc.platformAuth = in->newAuth;
            // orderly state should be cleared
            g_clearOrderly = TRUE;
            break;
        case TPM_RH_LOCKOUT:
            gp.lockoutAuth = in->newAuth;
            NV_SYNC_PERSISTENT(lockoutAuth);
            break;
        default:
            FAIL(FATAL_ERROR_INTERNAL);
            break;
    }

    return TPM_RC_SUCCESS;
}

#endif  // CC_HierarchyChangeAuth