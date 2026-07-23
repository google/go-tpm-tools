// Platform Initialization Functions
// Notify the platform the TPM is processing TpmInit.
// These are opportunities for the Platform to initialize its own data.
// Usually these are only called once (and could therefore be omitted by
// static variable initialization, but are useful in unit testing.

#ifndef _PLATFORM_INIT_FP_H_
#define _PLATFORM_INIT_FP_H_

// Notification at very start of TPM_Init();
LIB_EXPORT void _plat__StartTpmInit(void);

// Notification at very end of a SUCCESSFUL TPM_Init();
// if the TPM has failed TpmInit (and entered failure mode)
// this will not be called
LIB_EXPORT void _plat__EndOkTpmInit(void);

#endif  // _PLATFORM_INIT_FP_H_