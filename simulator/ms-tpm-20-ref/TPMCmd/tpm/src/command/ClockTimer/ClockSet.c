#include "Tpm.h"
#include "ClockSet_fp.h"

#if CC_ClockSet  // Conditional expansion of this file

// Read the current TPMS_TIMER_INFO structure settings
//  Return Type: TPM_RC
//      TPM_RC_NV_RATE              NV is unavailable because of rate limit
//      TPM_RC_NV_UNAVAILABLE       NV is inaccessible
//      TPM_RC_VALUE                invalid new clock

TPM_RC
TPM2_ClockSet(ClockSet_In* in  // IN: input parameter list
)
{
    // Input Validation
    // new time can not be bigger than 0xFFFF000000000000 or smaller than
    // current clock
    if(in->newTime > 0xFFFF000000000000ULL || in->newTime < go.clock)
        return TPM_RCS_VALUE + RC_ClockSet_newTime;

    // Internal Data Update
    // Can't modify the clock if NV is not available.
    RETURN_IF_NV_IS_NOT_AVAILABLE;

    TimeClockUpdate(in->newTime);
    return TPM_RC_SUCCESS;
}

#endif  // CC_ClockSet