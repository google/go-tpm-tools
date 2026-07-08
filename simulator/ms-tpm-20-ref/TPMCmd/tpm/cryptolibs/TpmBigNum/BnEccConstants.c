/*(Auto-generated)
 *  Created by TpmStructures; Version 4.4 Mar 26, 2019
 *  Date: Aug 30, 2019  Time: 02:11:52PM
 */
#include "TpmBigNum.h"
//#include "Tpm.h"
// TODO_RENAME_INC_FOLDER:private refers to the TPM_CoreLib private headers
#include <private/OIDs.h>

#if ALG_ECC

// define macros expected by EccConstantData to convert the data to BigNum format

#  define TO_ECC_64                      TO_CRYPT_WORD_64
#  define TO_ECC_56(a, b, c, d, e, f, g) TO_ECC_64(0, a, b, c, d, e, f, g)
#  define TO_ECC_48(a, b, c, d, e, f)    TO_ECC_64(0, 0, a, b, c, d, e, f)
#  define TO_ECC_40(a, b, c, d, e)       TO_ECC_64(0, 0, 0, a, b, c, d, e)
#  if RADIX_BITS > 32
#    define TO_ECC_32(a, b, c, d) TO_ECC_64(0, 0, 0, 0, a, b, c, d)
#    define TO_ECC_24(a, b, c)    TO_ECC_64(0, 0, 0, 0, 0, a, b, c)
#    define TO_ECC_16(a, b)       TO_ECC_64(0, 0, 0, 0, 0, 0, a, b)
#    define TO_ECC_8(a)           TO_ECC_64(0, 0, 0, 0, 0, 0, 0, a)
#  else  // RADIX_BITS == 32
#    define TO_ECC_32          BIG_ENDIAN_BYTES_TO_UINT32
#    define TO_ECC_24(a, b, c) TO_ECC_32(0, a, b, c)
#    define TO_ECC_16(a, b)    TO_ECC_32(0, 0, a, b)
#    define TO_ECC_8(a)        TO_ECC_32(0, 0, 0, a)
#  endif
#  define TO_ECC_192(a, b, c)                      c, b, a
#  define TO_ECC_224(a, b, c, d)                   d, c, b, a
#  define TO_ECC_256(a, b, c, d)                   d, c, b, a
#  define TO_ECC_384(a, b, c, d, e, f)             f, e, d, c, b, a
#  define TO_ECC_528(a, b, c, d, e, f, g, h, i)    i, h, g, f, e, d, c, b, a
#  define TO_ECC_640(a, b, c, d, e, f, g, h, i, j) j, i, h, g, f, e, d, c, b, a

#  define BN_MIN_ALLOC(bytes) \
      (BYTES_TO_CRYPT_WORDS(bytes) == 0) ? 1 : BYTES_TO_CRYPT_WORDS(bytes)
#  define ECC_CONST(NAME, bytes, initializer)                   \
      const struct                                              \
      {                                                         \
          crypt_uword_t allocate, size, d[BN_MIN_ALLOC(bytes)]; \
      } NAME = {BN_MIN_ALLOC(bytes), BYTES_TO_CRYPT_WORDS(bytes), {initializer}}

// This file contains the raw data for ECC curve constants. The data is wrapped
// in macros so this file can be included in other files that format the data in
// a memory format desired by the user.  This file itself is never used alone.
#  include <EccConstantData.inl>

// now define the TPMBN_ECC_CURVE_CONSTANTS objects for the known curves

#  if ECC_NIST_P192
const TPMBN_ECC_CURVE_CONSTANTS NIST_P192 = {TPM_ECC_NIST_P192,
                                             (bigNum)&NIST_P192_p,
                                             (bigNum)&NIST_P192_n,
                                             (bigNum)&NIST_P192_h,
                                             (bigNum)&NIST_P192_a,
                                             (bigNum)&NIST_P192_b,
                                             {(bigNum)&NIST_P192_gX,
                                              (bigNum)&NIST_P192_gY,
                                              (bigNum)&NIST_P192_gZ}};
#  endif  // ECC_NIST_P192

#  if ECC_NIST_P224
const TPMBN_ECC_CURVE_CONSTANTS NIST_P224 = {TPM_ECC_NIST_P224,
                                             (bigNum)&NIST_P224_p,
                                             (bigNum)&NIST_P224_n,
                                             (bigNum)&NIST_P224_h,
                                             (bigNum)&NIST_P224_a,
                                             (bigNum)&NIST_P224_b,
                                             {(bigNum)&NIST_P224_gX,
                                              (bigNum)&NIST_P224_gY,
                                              (bigNum)&NIST_P224_gZ}};
#  endif  // ECC_NIST_P224

#  if ECC_NIST_P256
const TPMBN_ECC_CURVE_CONSTANTS NIST_P256 = {TPM_ECC_NIST_P256,
                                             (bigNum)&NIST_P256_p,
                                             (bigNum)&NIST_P256_n,
                                             (bigNum)&NIST_P256_h,
                                             (bigNum)&NIST_P256_a,
                                             (bigNum)&NIST_P256_b,
                                             {(bigNum)&NIST_P256_gX,
                                              (bigNum)&NIST_P256_gY,
                                              (bigNum)&NIST_P256_gZ}};
#  endif  // ECC_NIST_P256

#  if ECC_NIST_P384
const TPMBN_ECC_CURVE_CONSTANTS NIST_P384 = {TPM_ECC_NIST_P384,
                                             (bigNum)&NIST_P384_p,
                                             (bigNum)&NIST_P384_n,
                                             (bigNum)&NIST_P384_h,
                                             (bigNum)&NIST_P384_a,
                                             (bigNum)&NIST_P384_b,
                                             {(bigNum)&NIST_P384_gX,
                                              (bigNum)&NIST_P384_gY,
                                              (bigNum)&NIST_P384_gZ}};
#  endif  // ECC_NIST_P384

#  if ECC_NIST_P521
const TPMBN_ECC_CURVE_CONSTANTS NIST_P521 = {TPM_ECC_NIST_P521,
                                             (bigNum)&NIST_P521_p,
                                             (bigNum)&NIST_P521_n,
                                             (bigNum)&NIST_P521_h,
                                             (bigNum)&NIST_P521_a,
                                             (bigNum)&NIST_P521_b,
                                             {(bigNum)&NIST_P521_gX,
                                              (bigNum)&NIST_P521_gY,
                                              (bigNum)&NIST_P521_gZ}};
#  endif  // ECC_NIST_P521

#  if ECC_BN_P256
const TPMBN_ECC_CURVE_CONSTANTS BN_P256 = {TPM_ECC_BN_P256,
                                           (bigNum)&BN_P256_p,
                                           (bigNum)&BN_P256_n,
                                           (bigNum)&BN_P256_h,
                                           (bigNum)&BN_P256_a,
                                           (bigNum)&BN_P256_b,
                                           {(bigNum)&BN_P256_gX,
                                            (bigNum)&BN_P256_gY,
                                            (bigNum)&BN_P256_gZ}};
#  endif  // ECC_BN_P256

#  if ECC_BN_P638
const TPMBN_ECC_CURVE_CONSTANTS BN_P638 = {TPM_ECC_BN_P638,
                                           (bigNum)&BN_P638_p,
                                           (bigNum)&BN_P638_n,
                                           (bigNum)&BN_P638_h,
                                           (bigNum)&BN_P638_a,
                                           (bigNum)&BN_P638_b,
                                           {(bigNum)&BN_P638_gX,
                                            (bigNum)&BN_P638_gY,
                                            (bigNum)&BN_P638_gZ}};
#  endif  // ECC_BN_P638

#  if ECC_SM2_P256
const TPMBN_ECC_CURVE_CONSTANTS SM2_P256 = {TPM_ECC_SM2_P256,
                                            (bigNum)&SM2_P256_p,
                                            (bigNum)&SM2_P256_n,
                                            (bigNum)&SM2_P256_h,
                                            (bigNum)&SM2_P256_a,
                                            (bigNum)&SM2_P256_b,
                                            {(bigNum)&SM2_P256_gX,
                                             (bigNum)&SM2_P256_gY,
                                             (bigNum)&SM2_P256_gZ}};
#  endif  // ECC_SM2_P256

#  define comma
const TPMBN_ECC_CURVE_CONSTANTS* bnEccCurveData[] = {
#  if ECC_NIST_P192
    &NIST_P192,
#  endif
#  if ECC_NIST_P224
    &NIST_P224,
#  endif
#  if ECC_NIST_P256
    &NIST_P256,
#  endif
#  if ECC_NIST_P384
    &NIST_P384,
#  endif
#  if ECC_NIST_P521
    &NIST_P521,
#  endif
#  if ECC_BN_P256
    &BN_P256,
#  endif
#  if ECC_BN_P638
    &BN_P638,
#  endif
#  if ECC_SM2_P256
    &SM2_P256,
#  endif
};

MUST_BE((sizeof(bnEccCurveData) / sizeof(bnEccCurveData[0])) == (ECC_CURVE_COUNT));

//*** BnGetCurveData()
// This function returns the pointer for the constant parameter data
// associated with a curve.
const TPMBN_ECC_CURVE_CONSTANTS* BnGetCurveData(TPM_ECC_CURVE curveId)
{
    for(int i = 0; i < ECC_CURVE_COUNT; i++)
    {
        if(bnEccCurveData[i]->curveId == curveId)
            return bnEccCurveData[i];
    }
    return NULL;
}

#endif  // TPM_ALG_ECC
