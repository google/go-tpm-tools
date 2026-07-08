/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Apr  2, 2019  Time: 11:00:49AM
 */

#ifndef _POWER_FP_H_
#define _POWER_FP_H_

//*** TPMInit()
// This function is used to process a power on event.
void TPMInit(void);

//*** TPMRegisterStartup()
// This function registers the fact that the TPM has been initialized
// (a TPM2_Startup() has completed successfully).
BOOL TPMRegisterStartup(void);

//*** TPMIsStarted()
// Indicates if the TPM has been initialized (a TPM2_Startup() has completed
// successfully after a _TPM_Init).
//  Return Type: BOOL
//      TRUE(1)         TPM has been initialized
//      FALSE(0)        TPM has not been initialized
BOOL TPMIsStarted(void);

#endif  // _POWER_FP_H_
