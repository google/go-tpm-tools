/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Apr  2, 2019  Time: 03:18:00PM
 */

#ifndef _TPM_FAIL_FP_H_
#define _TPM_FAIL_FP_H_

//*** EnterFailureMode()
// This function is called by TPM.lib when a failure occurs. It will set up the
// failure values to be returned on TPM2_GetTestResult().
NORETURN_IF_LONGJMP void EnterFailureMode(
#if FAIL_TRACE
    const char* function,
    int         line,
#endif
    uint64_t locationCode,
    int      failureCode);

//*** TpmFailureMode(
// This function is called by the interface code when the platform is in failure
// mode.
void TpmFailureMode(uint32_t        inRequestSize,    // IN: command buffer size
                    unsigned char*  inRequest,        // IN: command buffer
                    uint32_t*       outResponseSize,  // OUT: response buffer size
                    unsigned char** outResponse       // OUT: response buffer
);

#endif  // _TPM_FAIL_FP_H_
