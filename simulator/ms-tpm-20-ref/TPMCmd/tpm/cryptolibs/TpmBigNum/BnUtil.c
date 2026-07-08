//** Introduction
// Utility functions to support TpmBigNum library

#include "TpmBigNum.h"
#include <CryptoInterface.h>

#if CRYPTO_LIB_REPORTING

//*** _crypto_GetMathImpl()
// Report the library being used for math.
void _crypto_GetMathImpl(_CRYPTO_IMPL_DESCRIPTION* result)
{
    // TpmmBigNum relies on a sub-library for its implementation.
    // Query the sub-library being used and use that to fill out the response.
    _CRYPTO_IMPL_DESCRIPTION subResult;
    BnGetImplementation(&subResult);

    // _CRYPTO_IMPL_DESCRIPTION has room for 31 characters plus NUL, and we use
    // 10 characters for the prefix "TPMBigNum/".
    // Using '%.21s' in snprintf below allows us to be safe and explicit about
    // the fact that we expect truncation of the name of the bignum sub-provider
    // in the event that its name is too long.
    snprintf(result->name, sizeof(result->name), "TPMBigNum/%.21s", subResult.name);
    snprintf(result->version, sizeof(result->version), "%s", subResult.version);
}

#endif  // CRYPTO_LIB_REPORTING
