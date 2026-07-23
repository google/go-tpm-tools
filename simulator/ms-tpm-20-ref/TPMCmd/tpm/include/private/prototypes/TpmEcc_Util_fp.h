#ifndef _TPMECC_UTIL_FP_H_
#define _TPMECC_UTIL_FP_H_

#if ALG_ECC

//*** TpmEcc_PointFrom2B()
// Function to create a Crypt_Point structure from a 2B point.
// This function doesn't take an Crypt_EccCurve for legacy reasons -
// this should probably be changed.
// returns NULL if the input value is invalid or doesn't fit.
LIB_EXPORT Crypt_Point* TpmEcc_PointFrom2B(
    Crypt_Point*    ecP,  // OUT: the preallocated point structure
    TPMS_ECC_POINT* p     // IN: the number to convert
);

//*** TpmEcc_PointTo2B()
// This function converts a Crypt_Point into a TPMS_ECC_POINT. A TPMS_ECC_POINT
// contains two TPM2B_ECC_PARAMETER values. The maximum size of the parameters
// is dependent on the maximum EC key size used in an implementation.
// The presumption is that the TPMS_ECC_POINT is large enough to hold 2 TPM2B
// values, each as large as a MAX_ECC_PARAMETER_BYTES
LIB_EXPORT BOOL TpmEcc_PointTo2B(
    TPMS_ECC_POINT*       p,    // OUT: the converted 2B structure
    const Crypt_Point*    ecP,  // IN: the values to be converted
    const Crypt_EccCurve* E     // IN: curve descriptor for the point
);

#endif  // ALG_ECC
#endif  // _TPMECC_UTIL_FP_H_