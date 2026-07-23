#include "Tpm.h"
#include "ClearControl_fp.h"

#if CC_ClearControl  // Conditional expansion of this file

/*(See part 3 specification)
// Enable or disable the execution of TPM2_Clear command
*/
//  Return Type: TPM_RC
//      TPM_RC_AUTH_FAIL            authorization is not properly given
TPM_RC
TPM2_ClearControl(ClearControl_In* in  // IN: input parameter list
)
{
    // The command needs NV update.
    RETURN_IF_NV_IS_NOT_AVAILABLE;

    // Input Validation

    // LockoutAuth may be used to set disableLockoutClear to TRUE but not to FALSE
    if(in->auth == TPM_RH_LOCKOUT && in->disable == NO)
        return TPM_RC_AUTH_FAIL;

    // Internal Data Update

    if(in->disable == YES)
        gp.disableClear = TRUE;
    else
        gp.disableClear = FALSE;

    // Record the change to NV
    NV_SYNC_PERSISTENT(disableClear);

    return TPM_RC_SUCCESS;
}

#endif  // CC_ClearControl