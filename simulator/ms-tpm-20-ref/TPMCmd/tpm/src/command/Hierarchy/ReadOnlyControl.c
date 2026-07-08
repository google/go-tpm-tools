#include "Tpm.h"
#include "ReadOnlyControl_fp.h"

#if CC_ReadOnlyControl  // Conditional expansion of this file

/*(See part 3 specification)
// Enable or disable read-only mode of operation
*/
TPM_RC
TPM2_ReadOnlyControl(ReadOnlyControl_In* in  // IN: input parameter list
)
{
    if(in->state != gc.readOnly)
    {
        // Before changing the internal state, make sure that NV is available.
        // Only need to update NV if changing the orderly state
        RETURN_IF_ORDERLY;

        // modify the read-only state
        gc.readOnly = in->state;

        // orderly state should be cleared because of the update to state clear data
        // This gets processed in ExecuteCommand() on the way out.
        g_clearOrderly = TRUE;
    }
    return TPM_RC_SUCCESS;
}

#endif  // CC_ReadOnlyControl
