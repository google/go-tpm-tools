//** Introduction
//
// The functions in this file are used for initialization of the interface to the
// OpenSSL library.

//** Defines and Includes

#include "BnOssl.h"
#include <CryptoInterface.h>
#include <Ossl/TpmToOsslSym.h>
#include <Ossl/TpmToOsslHash.h>
#include <openssl/opensslv.h>
#include <stdio.h>

#if CRYPTO_LIB_REPORTING

//*** OsslGetVersion()
// Report the version of OpenSSL.
void OsslGetVersion(_CRYPTO_IMPL_DESCRIPTION* result)
{
    snprintf(result->name, sizeof(result->name), "OpenSSL");
#  if defined(OPENSSL_VERSION_STR)
    snprintf(result->version, sizeof(result->version), "%s", OPENSSL_VERSION_STR);
#  else
    // decode the hex version string according to the rules described in opensslv.h
    snprintf(result->version,
             sizeof(result->version),
             "%d.%d.%d%c",
             (unsigned char)((OPENSSL_VERSION_NUMBER >> 28) & 0x0f),
             (unsigned char)((OPENSSL_VERSION_NUMBER >> 20) & 0xff),
             (unsigned char)((OPENSSL_VERSION_NUMBER >> 12) & 0xff),
             (char)((OPENSSL_VERSION_NUMBER >> 4) & 0xff) - 1 + 'a');
#  endif  //OPENSSL_VERSION_STR
}

#endif  //CRYPTO_LIB_REPORTING

#if defined(HASH_LIB_OSSL) || defined(MATH_LIB_OSSL) || defined(SYM_LIB_OSSL)
// Used to pass the pointers to the correct sub-keys
typedef const BYTE* desKeyPointers[3];

//*** BnSupportLibInit()
// This does any initialization required by the support library.
LIB_EXPORT int BnSupportLibInit(void)
{
    return TRUE;
}

//*** OsslContextEnter()
// This function is used to initialize an OpenSSL context at the start of a function
// that will call to an OpenSSL math function.
BN_CTX* OsslContextEnter(void)
{
    BN_CTX* CTX = BN_CTX_new();
    //
    return OsslPushContext(CTX);
}

//*** OsslContextLeave()
// This is the companion function to OsslContextEnter().
void OsslContextLeave(BN_CTX* CTX)
{
    OsslPopContext(CTX);
    BN_CTX_free(CTX);
}

//*** OsslPushContext()
// This function is used to create a frame in a context. All values allocated within
// this context after the frame is started will be automatically freed when the
// context (OsslPopContext()
BN_CTX* OsslPushContext(BN_CTX* CTX)
{
    if(CTX == NULL)
        FAIL(FATAL_ERROR_ALLOCATION);
    BN_CTX_start(CTX);
    return CTX;
}

//*** OsslPopContext()
// This is the companion function to OsslPushContext().
void OsslPopContext(BN_CTX* CTX)
{
    // BN_CTX_end can't be called with NULL. It will blow up.
    if(CTX != NULL)
        BN_CTX_end(CTX);
}

#  if CRYPTO_LIB_REPORTING

#    if defined(SYM_LIB_OSSL) && SIMULATION && CRYPTO_LIB_REPORTING
//*** _crypto_GetSymImpl()
// Report the version of OpenSSL being used for symmetric crypto.
void _crypto_GetSymImpl(_CRYPTO_IMPL_DESCRIPTION* result)
{
    OsslGetVersion(result);
}
#    else
#      error huh?
#    endif  // defined(SYM_LIB_OSSL) && SIMULATION

#    if defined(HASH_LIB_OSSL) && SIMULATION && CRYPTO_LIB_REPORTING
//*** _crypto_GetHashImpl()
// Report the version of OpenSSL being used for hashing.
void _crypto_GetHashImpl(_CRYPTO_IMPL_DESCRIPTION* result)
{
    OsslGetVersion(result);
}
#    endif  // defined(HASH_LIB_OSSL) && SIMULATION

#  endif  // CRYPTO_LIB_REPORTING

#endif  // HASH_LIB_OSSL || MATH_LIB_OSSL || SYM_LIB_OSSL
