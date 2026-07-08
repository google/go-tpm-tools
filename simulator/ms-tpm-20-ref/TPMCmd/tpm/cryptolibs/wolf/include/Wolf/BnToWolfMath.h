
//** Introduction
// This file contains the structure definitions used for ECC in the LibTomCrypt
// version of the code. These definitions would change, based on the library.
// The ECC-related structures that cross the TPM interface are defined
// in TpmTypes.h
//

#ifndef _BN_TO_WOLF_MATH_H_
#define _BN_TO_WOLF_MATH_H_

#ifndef BN_MATH_LIB_DEFINED
#  define BN_MATH_LIB_DEFINED

#  define MATH_LIB_WOLF

// Require TPM Big Num types
#  ifndef MATH_LIB_TPMBIGNUM
#    error this Wolf Interface expects to be used from TpmBigNum
#  endif

#  if ALG_ECC
#    define HAVE_ECC
#  endif

#  include <wolfssl/wolfcrypt/tfm.h>
#  include <wolfssl/wolfcrypt/ecc.h>

#  define MP_VAR(name) \
      mp_int  _##name; \
      mp_int* name = MpInitialize(&_##name);

// Allocate a mp_int and initialize with the values in a mp_int* initializer
#  define MP_INITIALIZED(name, initializer) \
      MP_VAR(name);                         \
      BnToWolf(name, initializer);

#  define POINT_CREATE(name, initializer) \
      ecc_point* name = EcPointInitialized(initializer);

#  define POINT_DELETE(name)  \
      wc_ecc_del_point(name); \
      name = NULL;

// Note that this declaration results in Crypt_EccCurve being a pointer (and the
// usual usage oc Crypt_EccCurve* being a pointer-to-a-pointer). The extra
// indirection is allows CRYPT_CURVE_TYPE(b) to have consistent behavior so each
// sub-library doesn't need to implement separate CRYPT_CURVE_INITIALIZED macros, and
// it would be wasteful to create copies of the full TPMBN_ECC_CURVE_CONSTANTS
// structure for each usage.
typedef const TPMBN_ECC_CURVE_CONSTANTS*    bigCurveData;

TPM_INLINE const TPMBN_ECC_CURVE_CONSTANTS* AccessCurveConstants(
    const bigCurveData* E)
{
    return *E;
}

#  include "BnToWolfSupport_fp.h"

#  define WOLF_ENTER()

#  define WOLF_LEAVE()

// This definition would change if there were something to report
#  define MathLibSimulationEnd()
#else
#  error BN_MATH_LIB_DEFINED already defined
#endif  // BN_MATH_LIB_DEFINED
#endif  // _BN_TO_WOLF_MATH_H_
