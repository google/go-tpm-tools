#include "Platform.h"

// Notification at very start of TPM_Init();
LIB_EXPORT void _plat__StartTpmInit(void)
{
    // call platform reset functions, that have no TPM dependencies
    // needs the failure change
    _plat_internal_resetFailureData();
}

LIB_EXPORT void _plat__EndOkTpmInit(void)
{
    // call platform reset functions that depend on previous TPM initialization
    // (none in this implementation)
}
