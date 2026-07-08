//** Introduction
// This file contains debug utility functions to help testing Ecc.
#include "Tpm.h"
#include "TpmEcc_Util_fp.h"
#include "TpmMath_Debug_fp.h"

#if ALG_SM2
#  ifdef _SM2_SIGN_DEBUG

//*** SafeGetStringLength()
// self-implemented version of strnlen_s.  This is necessary because
// some environments don't have a C-runtime library, or are limited to
// C99, and strnlen_s was standardized in C11.
static size_t SafeGetStringLength(const char* string, size_t maxsize)
{
    // strnlen_s has two boundary conditions:
    // return 0 if pointer is nullptr, or
    // maxsize if no null character is found.
    if(string == NULL)
        return 0;

    const char* pos  = string;
    size_t      size = 0;

    while(*pos != '\0' && size < maxsize)
    {
        pos++;
        size++;
    }
    return size;
}

// convert from hex value.  If invalid, result will be out of range.
static LIB_EXPORT BYTE FromHex(unsigned char c)
{
    // hack for the ASCII characters we care about
    BYTE upper = (c & (~0x20));
    if(c >= '0' && c <= '9')
        return c - '0';
    else if(c >= 'A' && c <= 'F')
        return c - 'A';
    else if(c >= 'a' && c <= 'f')
        return c - 'a';

    return 255;
}

//*** TpmEccDebug_FromHex()
// Convert a hex string into a Crypt_Int*. This is primarily used in debugging.
LIB_EXPORT Crypt_Int* TpmEccDebug_FromHex(
    Crypt_Int*           bn,         // OUT:
    const unsigned char* hex,        // IN:
    size_t               maxsizeHex  // IN: maximum size of hex
)
{
    // if value is larger than this, then fail
    BYTE tempBuf[MAX_ECC_KEY_BYTES];
    MemorySet(tempBuf, 0, sizeof(tempBuf));
    ExtMath_SetWord(bn, 0);

    size_t len = SafeGetStringLength(hex, maxsizeHex);
    BOOL   OK  = FALSE;
    if((len % 2) == 0)
    {
        OK = TRUE;
        for(size_t i = 0; i < len; i += 2)
        {
            BYTE highNibble = FromHex(*hex);
            hex++;
            BYTE lowNibble = FromHex(*hex);
            hex++;
            // unsigned, no need to check zero
            if(highNibble > 15 || lowNibble > 15)
            {
                OK = FALSE;
                break;
            }
            BYTE b         = ((highNibble << 4) | lowNibble);
            tempBuf[i / 2] = b;
        }
        if(OK)
        {
            ExtMath_IntFromBytes(bn, tempBuf, (NUMBYTES)(len / 2));
        }
    }

    if(!OK)
    {
        // this should only be called in testing, so any
        // errors are fatal.
        FAIL(FATAL_ERROR_INTERNAL);
    }
    return bn;
}

//*** TpmEccDebug_HexEqual()
// This function compares a bignum value to a hex string.
// using TpmEcc namespace because code assumes the max size
// is correct for ECC.
//  Return Type: BOOL
//      TRUE(1)         values equal
//      FALSE(0)        values not equal
BOOL TpmEccDebug_HexEqual(const Crypt_Int* bn,  //IN: big number value
                          const char*      c    //IN: character string number
)
{
    CRYPT_ECC_NUM(bnC);
    TpmEccDebug_FromHex(bnC, c, MAX_ECC_KEY_BYTES * 2 + 1);
    return (ExtMath_UnsignedCmp(bn, bnC) == 0);
}
#  endif  // _SM2_SIGN_DEBUG
#endif    // ALG_SM2