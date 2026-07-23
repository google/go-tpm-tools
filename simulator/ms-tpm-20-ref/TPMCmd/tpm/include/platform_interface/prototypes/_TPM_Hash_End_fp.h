/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar 28, 2019  Time: 08:25:19PM
 */

#ifndef __TPM_HASH_END_FP_H_
#define __TPM_HASH_END_FP_H_

// This function is called to process a _TPM_Hash_End indication. Returns FALSE
// on failure.  If FALSE is returned caller should check for failure mode, (not
// all failures are fatal)
LIB_EXPORT BOOL _TPM_Hash_End(void);

#endif  // __TPM_HASH_END_FP_H_
