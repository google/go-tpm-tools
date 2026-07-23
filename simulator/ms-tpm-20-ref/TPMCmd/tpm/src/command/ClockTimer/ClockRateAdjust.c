#include "Tpm.h"
#include "ClockRateAdjust_fp.h"

#if CC_ClockRateAdjust  // Conditional expansion of this file

/*(See part 3 specification)
// adjusts the rate of advance of Clock and Timer to provide a better
// approximation to real time.
*/
TPM_RC
TPM2_ClockRateAdjust(ClockRateAdjust_In* in  // IN: input parameter list
)
{
    // Internal Data Update
    TimeSetAdjustRate(in->rateAdjust);

    return TPM_RC_SUCCESS;
}

#endif  // CC_ClockRateAdjust