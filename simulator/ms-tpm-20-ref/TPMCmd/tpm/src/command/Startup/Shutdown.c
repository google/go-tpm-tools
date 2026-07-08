#include "Tpm.h"
#include "Shutdown_fp.h"

#if CC_Shutdown  // Conditional expansion of this file

/*(See part 3 specification)
// Shut down TPM for power off
*/
//  Return Type: TPM_RC
//      TPM_RC_TYPE             if PCR bank has been re-configured, a
//                              Shutdown(CLEAR) is required
TPM_RC
TPM2_Shutdown(Shutdown_In* in  // IN: input parameter list
)
{
    // The command needs NV update.  Check if NV is available.
    // A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may be returned at
    // this point
    RETURN_IF_NV_IS_NOT_AVAILABLE;

    // Input Validation
    // If PCR bank has been reconfigured, a CLEAR state save is required
    if(g_pcrReConfig && in->shutdownType == TPM_SU_STATE)
        return TPM_RCS_TYPE + RC_Shutdown_shutdownType;
    // Internal Data Update
    gp.orderlyState = in->shutdownType;

#  if USE_DA_USED
    // CLEAR g_daUsed so that any future DA-protected access will cause the
    // shutdown to become non-orderly. It is not sufficient to invalidate the
    // shutdown state after a DA failure because an attacker can inhibit access
    // to NV and use the fact that an update of failedTries was attempted as an
    // indication of an authorization failure. By making sure that the orderly state
    // is CLEAR before any DA attempt, this prevents the possibility of this 'attack.'
    g_daUsed = FALSE;
#  endif

    // PCR private date state save
    PCRStateSave(in->shutdownType);

#  if ACT_SUPPORT
    // Save the ACT state
    ActShutdown(in->shutdownType);
#  endif

    // Save RAM backed NV index data
    NvUpdateIndexOrderlyData();

#  if ACCUMULATE_SELF_HEAL_TIMER
    // Save the current time value
    go.time = g_time;
#  endif

    // Save all orderly data
    NvWrite(NV_ORDERLY_DATA, sizeof(ORDERLY_DATA), &go);

    if(in->shutdownType == TPM_SU_STATE)
    {
        // Save STATE_RESET and STATE_CLEAR data
        NvWrite(NV_STATE_CLEAR_DATA, sizeof(STATE_CLEAR_DATA), &gc);
        NvWrite(NV_STATE_RESET_DATA, sizeof(STATE_RESET_DATA), &gr);

        // Save the startup flags for resume
        if(g_DrtmPreStartup)
            gp.orderlyState = TPM_SU_STATE | PRE_STARTUP_FLAG;
        else if(g_StartupLocality3)
            gp.orderlyState = TPM_SU_STATE | STARTUP_LOCALITY_3;
    }
    // only two shutdown options.
    else if(in->shutdownType != TPM_SU_CLEAR)
        return TPM_RCS_VALUE + RC_Shutdown_shutdownType;

    NV_SYNC_PERSISTENT(orderlyState);

    return TPM_RC_SUCCESS;
}
#endif  // CC_Shutdown