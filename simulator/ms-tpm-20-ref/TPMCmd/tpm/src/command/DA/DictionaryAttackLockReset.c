#include "Tpm.h"
#include "DictionaryAttackLockReset_fp.h"

#if CC_DictionaryAttackLockReset  // Conditional expansion of this file

/*(See part 3 specification)
// This command cancels the effect of a TPM lockout due to a number of
// successive authorization failures.  If this command is properly authorized,
// the lockout counter is set to 0.
*/
TPM_RC
TPM2_DictionaryAttackLockReset(
    DictionaryAttackLockReset_In* in  // IN: input parameter list
)
{
    // Input parameter is not reference in command action
    NOT_REFERENCED(in);

    // The command needs NV update.
    RETURN_IF_NV_IS_NOT_AVAILABLE;

    // Internal Data Update

    // Set failed tries to 0
    gp.failedTries = 0;

    // Record the changes to NV
    NV_SYNC_PERSISTENT(failedTries);

    return TPM_RC_SUCCESS;
}

#endif  // CC_DictionaryAttackLockReset