//** Introduction
// Prototypes for functions the bignum library requires
// from a bignum-based math support library.
// Functions contained in the MathInterface but not listed here are provided by
// the TpmBigNum library itself.
//
// This file contains the function prototypes for the functions that need to be
// present in the selected math library. For each function listed, there should
// be a small stub function. That stub provides the interface between the TPM
// code and the support library. In most cases, the stub function will only need
// to do a format conversion between the TPM big number and the support library
// big number. The TPM big number format was chosen to make this relatively
// simple and fast.
//
// Arithmetic operations return a BOOL to indicate if the operation completed
// successfully or not.

#ifndef BN_SUPPORT_INTERFACE_H
#define BN_SUPPORT_INTERFACE_H
// TODO_RENAME_INC_FOLDER:private refers to the TPM_CoreLib private headers
#include "tpm_public/GpMacros.h"
#include <CryptoInterface.h>
#include "BnValues.h"

//** BnSupportLibInit()
// This function is called by CryptInit() so that necessary initializations can be
// performed on the cryptographic library.
LIB_EXPORT
int BnSupportLibInit(void);

//** MathLibraryCompatibililtyCheck()
// This function is only used during development to make sure that the library
// that is being referenced is using the same size of data structures as the TPM.
BOOL BnMathLibraryCompatibilityCheck(void);

//** BnModMult()
// Does 'op1' * 'op2' and divide by 'modulus' returning the remainder of the divide.
LIB_EXPORT BOOL BnModMult(
    bigNum result, bigConst op1, bigConst op2, bigConst modulus);

//** BnMult()
// Multiplies two numbers and returns the result
LIB_EXPORT BOOL BnMult(bigNum result, bigConst multiplicand, bigConst multiplier);

//** BnDiv()
// This function divides two bigNum values. The function returns FALSE if there is
// an error in the operation.
LIB_EXPORT BOOL BnDiv(
    bigNum quotient, bigNum remainder, bigConst dividend, bigConst divisor);
//** BnMod()
#define BnMod(a, b) BnDiv(NULL, (a), (a), (b))

#if ALG_RSA
//** BnGcd()
// Get the greatest common divisor of two numbers. This function is only needed
// when the TPM implements RSA.
LIB_EXPORT BOOL BnGcd(bigNum gcd, bigConst number1, bigConst number2);

//** BnModExp()
// Do modular exponentiation using bigNum values. This function is only needed
// when the TPM implements RSA.
LIB_EXPORT BOOL BnModExp(
    bigNum result, bigConst number, bigConst exponent, bigConst modulus);
#endif  // ALG_RSA

//** BnModInverse()
// Modular multiplicative inverse.
LIB_EXPORT BOOL BnModInverse(bigNum result, bigConst number, bigConst modulus);

#if ALG_ECC

//** BnCurveInitialize()
// This function is used to initialize the pointers of a bigCurveData structure. The
// structure is a set of pointers to bigNum values. The curve-dependent values are
// set by a different function. This function is only needed
// if the TPM supports ECC.
LIB_EXPORT bigCurveData* BnCurveInitialize(bigCurveData* E, TPM_ECC_CURVE curveId);

//*** BnCurveFree()
// This function will free the allocated components of the curve and end the
// frame in which the curve data exists
LIB_EXPORT void BnCurveFree(bigCurveData* E);

//** BnEccModMult()
// This function does a point multiply of the form R = [d]S. A return of FALSE
// indicates that the result was the point at infinity. This function is only needed
// if the TPM supports ECC.
LIB_EXPORT BOOL BnEccModMult(
    bigPoint R, pointConst S, bigConst d, const bigCurveData* E);

//** BnEccModMult2()
// This function does a point multiply of the form R = [d]S + [u]Q. A return of
// FALSE indicates that the result was the point at infinity. This function is only
// needed if the TPM supports ECC.
LIB_EXPORT BOOL BnEccModMult2(bigPoint            R,
                              pointConst          S,
                              bigConst            d,
                              pointConst          Q,
                              bigConst            u,
                              const bigCurveData* E);

//** BnEccAdd()
// This function does a point add R = S + Q. A return of FALSE
// indicates that the result was the point at infinity. This function is only needed
// if the TPM supports ECC.
LIB_EXPORT BOOL BnEccAdd(
    bigPoint R, pointConst S, pointConst Q, const bigCurveData* E);

#endif  // ALG_ECC

#if CRYPTO_LIB_REPORTING

//** BnGetImplementation()
// This function reports the underlying library being used for bignum operations.
void BnGetImplementation(_CRYPTO_IMPL_DESCRIPTION* result);

#endif  // CRYPTO_LIB_REPORTING

#endif  //BN_SUPPORT_INTERFACE_H
