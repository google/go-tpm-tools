//** Introduction
// This file contains the declaration and initialization macros for
// low-level cryptographic buffer types.  This requires the underlying
// Crypto library to have already defined the CRYPT_INT_BUF family of
// macros.  See tpm_crypto_lib.md for details.

#ifndef MATH_LIBRARY_INTERFACE_TYPES_H
#define MATH_LIBRARY_INTERFACE_TYPES_H

#ifndef CRYPT_INT_BUF
#  error CRYPT_INT_BUF must be defined before including this file.
#endif
#ifndef CRYPT_POINT_BUF
#  error CRYPT_POINT_BUF must be defined before including this file.
#endif
#ifndef CRYPT_CURVE_BUF
#  error CRYPT_CURVE_BUF must be defined before including this file.
#endif

// Crypt_Int underlying types Crypt_Int is an abstract type that is used as a
// pointer. The underlying math library is expected to be able to find the
// actual allocated size for a given Crypt_Int object given a pointer to it, and
// therefore we typedef here to a size 1 (smallest possible).
typedef CRYPT_INT_BUF(one, 1) Crypt_Int;
typedef CRYPT_POINT_BUF(pointone, 1) Crypt_Point;
typedef CRYPT_CURVE_BUF(curvebuft, MAX_ECC_KEY_BITS) Crypt_EccCurve;

// produces bare typedef ci_<typename>_t
#define CRYPT_INT_TYPE(typename, bits) \
    typedef CRYPT_INT_BUF(ci_##typename##_buf_t, bits) ci_##typename##_t

// produces allocated `Crypt_Int* varname` backed by a
// stack buffer named `<varname>_buf`.  Initialization at the discretion of the
// ExtMath library.
#define CRYPT_INT_VAR(varname, bits)                         \
    CRYPT_INT_BUF(ci_##varname##_buf_t, bits) varname##_buf; \
    Crypt_Int* varname = ExtMath_Initialize_Int((Crypt_Int*)&(varname##_buf), bits);

// produces initialized `Crypt_Int* varname = (TPM2B) initializer` backed by a
// stack buffer named `<varname>_buf`
#define CRYPT_INT_INITIALIZED(varname, bits, initializer)           \
    CRYPT_INT_BUF(cibuf##varname, bits) varname##_buf;              \
    Crypt_Int* varname = TpmMath_IntFrom2B(                         \
        ExtMath_Initialize_Int((Crypt_Int*)&(varname##_buf), bits), \
        (TPM2B*)initializer);

// convenience variants of above:
// largest supported integer
#define CRYPT_INT_MAX(varname) CRYPT_INT_VAR(varname, LARGEST_NUMBER_BITS)

#define CRYPT_INT_MAX_INITIALIZED(name, initializer) \
    CRYPT_INT_INITIALIZED(name, LARGEST_NUMBER_BITS, initializer)

// A single RADIX_BITS value.
#define CRYPT_INT_WORD(name) CRYPT_INT_VAR(name, RADIX_BITS)

#define CRYPT_INT_WORD_INITIALIZED(varname, initializer)                  \
    CRYPT_INT_BUF(cibuf##varname, RADIX_BITS) varname##_buf;              \
    Crypt_Int* varname = ExtMath_SetWord(                                 \
        ExtMath_Initialize_Int((Crypt_Int*)&(varname##_buf), RADIX_BITS), \
        initializer);

// Crypt_EccCurve underlying types
#define CRYPT_CURVE_INITIALIZED(varname, initializer)             \
    CRYPT_CURVE_BUF(cv##varname, MAX_ECC_KEY_BITS) varname##_buf; \
    const Crypt_EccCurve* varname =                               \
        ExtEcc_CurveInitialize(&(varname##_buf), initializer)

/* no guarantee free will be called in the presence of longjmp */
#define CRYPT_CURVE_FREE(varname) ExtEcc_CurveFree(varname)

// Crypt_Point underlying types
#define CRYPT_POINT_VAR(varname)                                           \
    CRYPT_POINT_BUF(cp_##varname##_buf_t, MAX_ECC_KEY_BITS) varname##_buf; \
    Crypt_Point* varname =                                                 \
        ExtEcc_Initialize_Point((Crypt_Point*)&(varname##_buf), MAX_ECC_KEY_BITS);

#define CRYPT_POINT_INITIALIZED(varname, initValue)                                \
    CRYPT_POINT_BUF(cp_##varname##_buf_t, MAX_ECC_KEY_BITS) varname##_buf;         \
    Crypt_Point* varname = TpmEcc_PointFrom2B(                                     \
        ExtEcc_Initialize_Point((Crypt_Point*)&(varname##_buf), MAX_ECC_KEY_BITS), \
        initValue);

#endif  //MATH_LIBRARY_INTERFACE_TYPES_H
