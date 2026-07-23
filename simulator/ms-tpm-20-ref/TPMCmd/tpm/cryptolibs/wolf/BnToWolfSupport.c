
//** Introduction
//
// The functions in this file are used for initialization of the interface to the
// wolfSSL library.

//** Defines and Includes

#include "Tpm.h"

#if defined(HASH_LIB_WOLF) || defined(MATH_LIB_WOLF) || defined(SYM_LIB_WOLF)

//*** BnSupportLibInit()
// This does any initialization required by the support library.
LIB_EXPORT int BnSupportLibInit(void)
{
#  if LIBRARY_COMPATIBILITY_CHECK
    BnMathLibraryCompatibilityCheck();
#  endif
    return TRUE;
}

#  if CRYPTO_LIB_REPORTING

#    if defined(SYM_LIB_WOLF) && SIMULATION
//*** _crypto_GetSymImpl()
// Report the version of OpenSSL being used for symmetric crypto.
void _crypto_GetSymImpl(_CRYPTO_IMPL_DESCRIPTION* result)
{
    snprintf(result->name, sizeof(result->name), "WolfSSL");
    snprintf(result->version, sizeof(result->version), "n/a");
    // TODO: Populate version information based on whatever the WolfSSL
    // equivalent to opensslv.h is.
}
#    endif  // defined(SYM_LIB_WOLF) && SIMULATION

#    if defined(HASH_LIB_WOLF) && SIMULATION
//*** _crypto_GetHashImpl()
// Report the version of OpenSSL being used for hashing.
void _crypto_GetHashImpl(_CRYPTO_IMPL_DESCRIPTION* result)
{
    snprintf(result->name, sizeof(result->name), "WolfSSL");
    snprintf(result->version, sizeof(result->version), "n/a");
    // TODO: Populate version information based on whatever the WolfSSL
    // equivalent to opensslv.h is.
}
#    endif  // defined(HASH_LIB_WOLF) && SIMULATION

#  endif  // CRYPTO_LIB_REPORTING

#endif  // HASH_LIB_WOLF || MATH_LIB_WOLF || SYM_LIB_WOLF
