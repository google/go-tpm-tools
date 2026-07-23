#include "Tpm.h"
#include "ACT_SetTimeout_fp.h"

#if CC_ACT_SetTimeout  // Conditional expansion of this file

/*(See part 3 specification)
// prove an object with a specific Name is loaded in the TPM
*/
//  Return Type: TPM_RC
//      TPM_RC_RETRY            returned when an update for the selected ACT is
//                              already pending
//      TPM_RC_VALUE            attempt to disable signaling from an ACT that has
//                              not expired
TPM_RC
TPM2_ACT_SetTimeout(ACT_SetTimeout_In* in  // IN: input parameter list
)
{
    // If 'startTimeout' is UINT32_MAX, then this is an attempt to disable the ACT
    // and turn off the signaling for the ACT. This is only valid if the ACT
    // is signaling.
#  if ACT_SUPPORT
    if((in->startTimeout == UINT32_MAX) && !ActGetSignaled(in->actHandle))
        return TPM_RC_VALUE + RC_ACT_SetTimeout_startTimeout;
    return ActCounterUpdate(in->actHandle, in->startTimeout);
#  else   // ACT_SUPPORT
    NOT_REFERENCED(in);
    return TPM_RC_VALUE + RC_ACT_SetTimeout_startTimeout;
#  endif  // ACT_SUPPORT
}

#endif  // CC_ACT_SetTimeout