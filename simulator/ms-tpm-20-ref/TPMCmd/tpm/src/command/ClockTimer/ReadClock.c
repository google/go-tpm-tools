#include "Tpm.h"
#include "ReadClock_fp.h"

#if CC_ReadClock  // Conditional expansion of this file

/*(See part 3 specification)
// read the current TPMS_TIMER_INFO structure settings
*/
TPM_RC
TPM2_ReadClock(ReadClock_Out* out  // OUT: output parameter list
)
{
    // Command Output

    out->currentTime.time = g_time;
    TimeFillInfo(&out->currentTime.clockInfo);

    return TPM_RC_SUCCESS;
}

#endif  // CC_ReadClock