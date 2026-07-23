//
// debug and test utilities.  Not expected to be compiled into final products
#ifndef _TPMMATH_DEBUG_FP_H_
#define _TPMMATH_DEBUG_FP_H_

#if ALG_ECC || ALG_RSA

//*** TpmEccDebug_HexEqual()
// This function compares a bignum value to a hex string.
// using TpmEcc namespace because code assumes the max size
// is correct for ECC.
//  Return Type: BOOL
//      TRUE(1)         values equal
//      FALSE(0)        values not equal
BOOL TpmMath_Debug_HexEqual(const Crypt_Int* bn,  //IN: big number value
                            const char*      c    //IN: character string number
);

LIB_EXPORT Crypt_Int* TpmMath_Debug_FromHex(
    Crypt_Int*           bn,         // OUT:
    const unsigned char* hex,        // IN:
    size_t               maxsizeHex  // IN: maximum size of hex
);

#endif  // ALG_ECC or ALG_RSA
#endif  //_TPMMATH_DEBUG_FP_H_