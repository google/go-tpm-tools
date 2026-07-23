#include "Tpm.h"
#include "SetCommandCodeAuditStatus_fp.h"

#if CC_SetCommandCodeAuditStatus  // Conditional expansion of this file

/*(See part 3 specification)
// change the audit status of a command or to set the hash algorithm used for
// the audit digest.
*/
TPM_RC
TPM2_SetCommandCodeAuditStatus(
    SetCommandCodeAuditStatus_In* in  // IN: input parameter list
)
{

    // The command needs NV update.  Check if NV is available.
    // A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may be returned at
    // this point
    RETURN_IF_NV_IS_NOT_AVAILABLE;

    // Internal Data Update

    // Update hash algorithm
    if(in->auditAlg != TPM_ALG_NULL && in->auditAlg != gp.auditHashAlg)
    {
        // Can't change the algorithm and command list at the same time
        if(in->setList.count != 0 || in->clearList.count != 0)
            return TPM_RCS_VALUE + RC_SetCommandCodeAuditStatus_auditAlg;

        // Change the hash algorithm for audit
        gp.auditHashAlg = in->auditAlg;

        // Set the digest size to a unique value that indicates that the digest
        // algorithm has been changed. The size will be cleared to zero in the
        // command audit processing on exit.
        gr.commandAuditDigest.t.size = 1;

        // Save the change of command audit data (this sets g_updateNV so that NV
        // will be updated on exit.)
        NV_SYNC_PERSISTENT(auditHashAlg);
    }
    else
    {
        UINT32 i;
        BOOL   changed = FALSE;

        // Process set list
        for(i = 0; i < in->setList.count; i++)

            // If change is made in CommandAuditSet, set changed flag
            if(CommandAuditSet(in->setList.commandCodes[i]))
                changed = TRUE;

        // Process clear list
        for(i = 0; i < in->clearList.count; i++)
            // If change is made in CommandAuditClear, set changed flag
            if(CommandAuditClear(in->clearList.commandCodes[i]))
                changed = TRUE;

        // if change was made to command list, update NV
        if(changed)
            // this sets g_updateNV so that NV will be updated on exit.
            NV_SYNC_PERSISTENT(auditCommands);
    }

    return TPM_RC_SUCCESS;
}

#endif  // CC_SetCommandCodeAuditStatus