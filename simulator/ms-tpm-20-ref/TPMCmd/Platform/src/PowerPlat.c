//** Includes and Function Prototypes

#include "Platform.h"

//** Functions

//***_plat__Signal_PowerOn()
// Signal platform power on
LIB_EXPORT int _plat__Signal_PowerOn(void)
{
    // Reset the timer
    _plat__TimerReset();

    // Need to indicate that we lost power
    s_powerLost = TRUE;

    return 0;
}

//*** _plat__WasPowerLost()
// Test whether power was lost before a _TPM_Init.
//
// This function will clear the "hardware" indication of power loss before return.
// This means that there can only be one spot in the TPM code where this value
// gets read. This method is used here as it is the most difficult to manage in the
// TPM code and, if the hardware actually works this way, it is hard to make it
// look like anything else. So, the burden is placed on the TPM code rather than the
// platform code
//  Return Type: int
//      TRUE(1)         power was lost
//      FALSE(0)        power was not lost
LIB_EXPORT int _plat__WasPowerLost(void)
{
    int retVal  = s_powerLost;
    s_powerLost = FALSE;
    return retVal;
}

//*** _plat_Signal_Reset()
// This a TPM reset without a power loss.
LIB_EXPORT int _plat__Signal_Reset(void)
{
    // Initialize locality
    s_locality = 0;

    // Command cancel
    s_isCanceled = FALSE;

    _TPM_Init();

    // if we are doing reset but did not have a power failure, then we should
    // not need to reload NV ...

    return 0;
}

//***_plat__Signal_PowerOff()
// Signal platform power off
LIB_EXPORT void _plat__Signal_PowerOff(void)
{
    // Prepare NV memory for power off
    _plat__NVDisable((void*)FALSE, 0);

#if ACT_SUPPORT
    // Disable tick ACT tick processing
    _plat__ACT_EnableTicks(FALSE);
#endif

    return;
}