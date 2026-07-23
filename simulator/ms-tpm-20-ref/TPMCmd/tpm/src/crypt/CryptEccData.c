/*(Auto-generated)
 *  Created by TpmStructures; Version 4.4 Mar 26, 2019
 *  Date: Aug 30, 2019  Time: 02:11:52PM
 */

#include "Tpm.h"
#include "OIDs.h"

#if ALG_ECC

// This file contains the TPM Specific ECC curve metadata and pointers to the ecc-lib specific
// constant structure.
// The CURVE_NAME macro is used to remove the name string from normal builds, but leaves the
// string available in the initialization lists for potenial use during debugging by changing this
// macro (and the structure declaration)
#  define CURVE_NAME(N)

#  define comma
const TPM_ECC_CURVE_METADATA eccCurves[] = {
#  if ECC_NIST_P192
    comma{TPM_ECC_NIST_P192,
          192,
          {TPM_ALG_KDF1_SP800_56A, {{TPM_ALG_SHA256}}},
          {TPM_ALG_NULL, {{TPM_ALG_NULL}}},
          OID_ECC_NIST_P192 CURVE_NAME("NIST_P192")}
#    undef comma
#    define comma ,
#  endif  // ECC_NIST_P192
#  if ECC_NIST_P224
    comma{TPM_ECC_NIST_P224,
          224,
          {TPM_ALG_KDF1_SP800_56A, {{TPM_ALG_SHA256}}},
          {TPM_ALG_NULL, {{TPM_ALG_NULL}}},
          OID_ECC_NIST_P224 CURVE_NAME("NIST_P224")}
#    undef comma
#    define comma ,
#  endif  // ECC_NIST_P224
#  if ECC_NIST_P256
    comma{TPM_ECC_NIST_P256,
          256,
          {TPM_ALG_KDF1_SP800_56A, {{TPM_ALG_SHA256}}},
          {TPM_ALG_NULL, {{TPM_ALG_NULL}}},
          OID_ECC_NIST_P256 CURVE_NAME("NIST_P256")}
#    undef comma
#    define comma ,
#  endif  // ECC_NIST_P256
#  if ECC_NIST_P384
    comma{TPM_ECC_NIST_P384,
          384,
          {TPM_ALG_KDF1_SP800_56A, {{TPM_ALG_SHA384}}},
          {TPM_ALG_NULL, {{TPM_ALG_NULL}}},
          OID_ECC_NIST_P384 CURVE_NAME("NIST_P384")}
#    undef comma
#    define comma ,
#  endif  // ECC_NIST_P384
#  if ECC_NIST_P521
    comma{TPM_ECC_NIST_P521,
          521,
          {TPM_ALG_KDF1_SP800_56A, {{TPM_ALG_SHA512}}},
          {TPM_ALG_NULL, {{TPM_ALG_NULL}}},
          OID_ECC_NIST_P521 CURVE_NAME("NIST_P521")}
#    undef comma
#    define comma ,
#  endif  // ECC_NIST_P521
#  if ECC_BN_P256
    comma{TPM_ECC_BN_P256,
          256,
          {TPM_ALG_NULL, {{TPM_ALG_NULL}}},
          {TPM_ALG_NULL, {{TPM_ALG_NULL}}},
          OID_ECC_BN_P256 CURVE_NAME("BN_P256")}
#    undef comma
#    define comma ,
#  endif  // ECC_BN_P256
#  if ECC_BN_P638
    comma{TPM_ECC_BN_P638,
          638,
          {TPM_ALG_NULL, {{TPM_ALG_NULL}}},
          {TPM_ALG_NULL, {{TPM_ALG_NULL}}},
          OID_ECC_BN_P638 CURVE_NAME("BN_P638")}
#    undef comma
#    define comma ,
#  endif  // ECC_BN_P638
#  if ECC_SM2_P256
    comma{TPM_ECC_SM2_P256,
          256,
          {TPM_ALG_KDF1_SP800_56A, {{TPM_ALG_SM3_256}}},
          {TPM_ALG_NULL, {{TPM_ALG_NULL}}},
          OID_ECC_SM2_P256 CURVE_NAME("SM2_P256")}
#    undef comma
#    define comma ,
#  endif  // ECC_SM2_P256
};

#endif  // TPM_ALG_ECC
