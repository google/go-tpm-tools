/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar 28, 2019  Time: 08:25:19PM
 */

#ifndef _RESPONSE_CODE_PROCESSING_FP_H_
#define _RESPONSE_CODE_PROCESSING_FP_H_

//** RcSafeAddToResult()
// Adds a modifier to a response code as long as the response code allows a modifier
// and no modifier has already been added.
TPM_RC
RcSafeAddToResult(TPM_RC responseCode, TPM_RC modifier);

#endif  // _RESPONSE_CODE_PROCESSING_FP_H_
