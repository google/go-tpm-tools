/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar 28, 2019  Time: 08:25:19PM
 */

#ifndef _RSA_KEY_CACHE_FP_H_
#define _RSA_KEY_CACHE_FP_H_

#if USE_RSA_KEY_CACHE

//*** RsaKeyCacheControl()
// Used to enable and disable the RSA key cache.
LIB_EXPORT void RsaKeyCacheControl(int state);

//*** GetCachedRsaKey()
//  Return Type: BOOL
//      TRUE(1)         key loaded
//      FALSE(0)        key not loaded
BOOL GetCachedRsaKey(TPMT_PUBLIC*    publicArea,
                     TPMT_SENSITIVE* sensitive,
                     RAND_STATE*     rand  // IN: if not NULL, the deterministic
                                           //     RNG state
);
#endif  // defined SIMULATION && defined USE_RSA_KEY_CACHE

#endif  // _RSA_KEY_CACHE_FP_H_
