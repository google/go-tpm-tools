/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Oct 24, 2019  Time: 11:37:07AM
 */

#ifndef _TPM_SIZE_CHECKS_FP_H_
#define _TPM_SIZE_CHECKS_FP_H_

#if RUNTIME_SIZE_CHECKS

//** TpmSizeChecks()
// This function is used during the development process to make sure that the
// vendor-specific values result in a consistent implementation. When possible,
// the code contains "#if" to do compile-time checks. However, in some cases, the
// values require the use of "sizeof()" and that can't be used in an #if.
BOOL TpmSizeChecks(void);
#endif  // RUNTIME_SIZE_CHECKS

#endif  // _TPM_SIZE_CHECKS_FP_H_
