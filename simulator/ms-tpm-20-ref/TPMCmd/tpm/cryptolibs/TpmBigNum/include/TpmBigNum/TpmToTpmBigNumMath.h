//** Introduction
// This file contains OpenSSL specific functions called by TpmBigNum library to provide
// the TpmBigNum + OpenSSL math support.

#ifndef _TPM_TO_TPMBIGNUM_MATH_H_
#define _TPM_TO_TPMBIGNUM_MATH_H_

#ifdef MATH_LIB_DEFINED
#  error only one primary math library allowed
#endif
#define MATH_LIB_DEFINED

// indicate the TPMBIGNUM library is active
#define MATH_LIB_TPMBIGNUM

// TODO_RENAME_INC_FOLDER: private refers to the TPM_CoreLib private headers
#include <tpm_public/GpMacros.h>  // required for TpmFail_fp.h
#include <tpm_public/Capabilities.h>
#include <tpm_public/TpmTypes.h>  // requires capabilities & GpMacros
#include "BnValues.h"

#ifndef LIB_INCLUDE
#  error include ordering error, LIB_INCLUDE not defined
#endif
#ifndef BN_MATH_LIB
#  error BN_MATH_LIB not defined, required to provide BN library functions.
#endif

#if defined(CRYPT_CURVE_INITIALIZED) || defined(CRYPT_CURVE_FREE)
#error include ordering error, expected CRYPT_CURVE_INITIALIZED & CRYPT_CURVE_FREE to be undefined.
#endif

// Add support library dependent definitions.
// For TpmBigNum, we expect bigCurveData to be a defined type.
#include LIB_INCLUDE(BnTo, BN_MATH_LIB, Math)

#include "BnConvert_fp.h"
#include "BnMath_fp.h"
#include "BnMemory_fp.h"
#include "BnSupport_Interface.h"

// Define macros and types necessary for the math library abstraction layer
// Create a data object backing a Crypt_Int big enough for the given number of
// data bits
#define CRYPT_INT_BUF(buftypename, bits) BN_STRUCT(buftypename, bits)

// Create a data object backing a Crypt_Point big enough for the given number of
// data bits, per coordinate
#define CRYPT_POINT_BUF(buftypename, bits) BN_POINT_BUF(buftypename, bits)

// Create an instance of a data object underlying Crypt_EccCurve on the stack
// sufficient for given bit size.  In our case, all are the same size.
#define CRYPT_CURVE_BUF(buftypename, max_size_in_bits) bigCurveData

// now include the math library functional interface and instantiate the
// Crypt_Int & related types
// TODO_RENAME_INC_FOLDER: This should have a Tpm_Cryptolib_Common component prefix.
#include <MathLibraryInterface.h>

#endif  // _TPM_TO_TPMBIGNUM_MATH_H_
