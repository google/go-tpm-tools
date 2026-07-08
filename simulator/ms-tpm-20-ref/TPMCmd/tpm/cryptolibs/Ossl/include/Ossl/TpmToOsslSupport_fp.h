/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar 28, 2019  Time: 08:25:19PM
 */

#ifndef _TPM_TO_OSSL_SUPPORT_FP_H_
#define _TPM_TO_OSSL_SUPPORT_FP_H_

#if defined(HASH_LIB_OSSL) || defined(MATH_LIB_OSSL) || defined(SYM_LIB_OSSL)

//*** BnSupportLibInit()
// This does any initialization required by the support library.
LIB_EXPORT int BnSupportLibInit(void);

//*** OsslContextEnter()
// This function is used to initialize an OpenSSL context at the start of a function
// that will call to an OpenSSL math function.
BN_CTX* OsslContextEnter(void);

//*** OsslContextLeave()
// This is the companion function to OsslContextEnter().
void OsslContextLeave(BN_CTX* CTX);

//*** OsslPushContext()
// This function is used to create a frame in a context. All values allocated within
// this context after the frame is started will be automatically freed when the
// context (OsslPopContext()
BN_CTX* OsslPushContext(BN_CTX* CTX);

//*** OsslPopContext()
// This is the companion function to OsslPushContext().
void OsslPopContext(BN_CTX* CTX);
#endif  // HASH_LIB_OSSL || MATH_LIB_OSSL || SYM_LIB_OSSL

#endif  // _TPM_TO_OSSL_SUPPORT_FP_H_
