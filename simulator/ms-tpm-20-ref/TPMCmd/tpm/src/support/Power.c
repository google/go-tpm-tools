//** Description

// This file contains functions that receive the simulated power state
// transitions of the TPM.

//** Includes and Data Definitions
#define POWER_C
#include "Tpm.h"

//** Functions

//*** TPMInit()
// This function is used to process a power on event.
void TPMInit(void)
{
    // Set state as not initialized. This means that Startup is required
    g_initialized = FALSE;
    return;
}

//*** TPMRegisterStartup()
// This function registers the fact that the TPM has been initialized
// (a TPM2_Startup() has completed successfully).
BOOL TPMRegisterStartup(void)
{
    g_initialized = TRUE;
    return TRUE;
}

//*** TPMIsStarted()
// Indicates if the TPM has been initialized (a TPM2_Startup() has completed
// successfully after a _TPM_Init).
//  Return Type: BOOL
//      TRUE(1)         TPM has been initialized
//      FALSE(0)        TPM has not been initialized
BOOL TPMIsStarted(void)
{
    return g_initialized;
}
