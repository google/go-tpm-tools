//** Introduction
//
// This file contains the function prototypes for the functions that need to be
// present in the selected math library. For each function listed, there should
// be a small stub function. That stub provides the interface between the TPM
// code and the support library. In most cases, the stub function will only need
// to do a format conversion between the Crypt_* formats to the internal support
// library format.  Since the external library also provides the buffer macros
// for the underlying types, this is typically just a cast from the TPM type to
// the internal type.
//
// Arithmetic operations return a BOOL to indicate if the operation completed
// successfully or not.

#ifndef MATH_LIBRARY_INTERFACE_H
#define MATH_LIBRARY_INTERFACE_H

// Types
#include "MathLibraryInterfaceTypes.h"

// ***************************************************************************
// Library Level Functions
// ***************************************************************************

//** ExtMath_LibInit()
// This function is called by CryptInit() so that necessary initializations can be
// performed on the cryptographic library.
LIB_EXPORT int ExtMath_LibInit(void);

//** MathLibraryCompatibililtyCheck()
// This function is only used during development to make sure that the library
// that is being referenced is using the same size of data structures as the TPM.
LIB_EXPORT BOOL ExtMath_Debug_CompatibilityCheck(void);

// ***************************************************************************
// Integer/Number Functions (non-ECC)
// ***************************************************************************

// #################
// type initializers
// #################

//** ExtMath_Initialize_Int()
// Initialize* functions tells the Crypt_Int types how large of a value it can
// contain which is a compile time constant
LIB_EXPORT Crypt_Int* ExtMath_Initialize_Int(Crypt_Int* buffer, NUMBYTES bits);

// #################
// Buffer Converters
// #################
// convert TPM2B byte datainto the private format. The Crypt_Int must already be
// initialized with it's maximum size. Byte-based Initializers must be MSB first
// (TPM external format).
LIB_EXPORT Crypt_Int* ExtMath_IntFromBytes(
    Crypt_Int* buffer, const BYTE* input, NUMBYTES byteCount);
// Convert Crypt_Int into external format as a byte array.
LIB_EXPORT BOOL ExtMath_IntToBytes(
    const Crypt_Int* value, BYTE* output, NUMBYTES* pByteCount);
// Set Crypt_Int to a given small value. Words are native format.
LIB_EXPORT Crypt_Int* ExtMath_SetWord(Crypt_Int* buffer, crypt_uword_t word);

// #################
// Copy Functions
// #################

//*** ExtMath_Copy()
// Function to copy a bignum_t. If the output is NULL, then
// nothing happens. If the input is NULL, the output is set to zero.
LIB_EXPORT BOOL ExtMath_Copy(Crypt_Int* out, const Crypt_Int* in);

// ###############################
// Ordinary Arithmetic, writ large
// ###############################

//** ExtMath_Multiply()
// Multiplies two numbers and returns the result
LIB_EXPORT BOOL ExtMath_Multiply(
    Crypt_Int* result, const Crypt_Int* multiplicand, const Crypt_Int* multiplier);

//** ExtMath_Divide()
// This function divides two Crypt_Int* values. The function returns FALSE if there is
// an error in the operation. Quotient may be null, in which case this function returns
// only the remainder.
LIB_EXPORT BOOL ExtMath_Divide(Crypt_Int*       quotient,
                               Crypt_Int*       remainder,
                               const Crypt_Int* dividend,
                               const Crypt_Int* divisor);

//** ExtMath_GCD()
// Get the greatest common divisor of two numbers. This function is only needed
// when the TPM implements RSA.
LIB_EXPORT BOOL ExtMath_GCD(
    Crypt_Int* gcd, const Crypt_Int* number1, const Crypt_Int* number2);

//*** ExtMath_Add()
// This function adds two Crypt_Int* values. This function always returns TRUE.
LIB_EXPORT BOOL ExtMath_Add(
    Crypt_Int* result, const Crypt_Int* op1, const Crypt_Int* op2);

//*** ExtMath_AddWord()
// This function adds a word value to a Crypt_Int*. This function always returns TRUE.
LIB_EXPORT BOOL ExtMath_AddWord(
    Crypt_Int* result, const Crypt_Int* op, crypt_uword_t word);

//*** ExtMath_Subtract()
// This function does subtraction of two Crypt_Int* values and returns result = op1 - op2
// when op1 is greater than op2. If op2 is greater than op1, then a fault is
// generated. This function always returns TRUE.
LIB_EXPORT BOOL ExtMath_Subtract(
    Crypt_Int* result, const Crypt_Int* op1, const Crypt_Int* op2);

//*** ExtMath_SubtractWord()
// This function subtracts a word value from a Crypt_Int*. This function always
// returns TRUE.
LIB_EXPORT BOOL ExtMath_SubtractWord(
    Crypt_Int* result, const Crypt_Int* op, crypt_uword_t word);

// ###############################
// Modular Arithmetic, writ large
// ###############################

//** ExtMath_Mod()
// compute valueAndResult = valueAndResult mod modulus
// This function divides two Crypt_Int* values and returns only the remainder,
// replacing the original dividend. The function returns FALSE if there is an
// error in the operation.
LIB_EXPORT BOOL ExtMath_Mod(Crypt_Int* valueAndResult, const Crypt_Int* modulus);

//** ExtMath_ModMult()
// Compute result = (op1 * op2) mod modulus
LIB_EXPORT BOOL ExtMath_ModMult(Crypt_Int*       result,
                                const Crypt_Int* op1,
                                const Crypt_Int* op2,
                                const Crypt_Int* modulus);

//** ExtMath_ModExp()
// Compute result = (number ^ exponent) mod modulus
// where ^ indicates exponentiation.
// This function is only needed when the TPM implements RSA.
LIB_EXPORT BOOL ExtMath_ModExp(Crypt_Int*       result,
                               const Crypt_Int* number,
                               const Crypt_Int* exponent,
                               const Crypt_Int* modulus);

//** ExtMath_ModInverse()
// Compute the modular multiplicative inverse.
// result = (number ^ -1) mod modulus
// This function is only needed when the TPM implements RSA.
LIB_EXPORT BOOL ExtMath_ModInverse(
    Crypt_Int* result, const Crypt_Int* number, const Crypt_Int* modulus);

//** ExtMath_ModInversePrime()
// Compute the modular multiplicative inverse. This is an optimized function for
// the case where the modulus is known to be prime.
//
// CAUTION: Depending on the library implementation this may be much faster than
// the normal ModInverse, and therefore is subject to exposing the fact the
// modulus is prime via a timing side-channel. In many cases (e.g. ECC primes),
// the prime is not sensitive and this optimized route can be used.
LIB_EXPORT BOOL ExtMath_ModInversePrime(
    Crypt_Int* result, const Crypt_Int* number, const Crypt_Int* primeModulus);

//*** ExtMath_ModWord()
// compute numerator
// This function does modular division of a big number when the modulus is a
// word value.
LIB_EXPORT crypt_word_t ExtMath_ModWord(const Crypt_Int* numerator,
                                        crypt_word_t     modulus);

// ###############################
// Queries
// ###############################

//*** ExtMath_UnsignedCmp()
// This function performs a comparison of op1 to op2. The compare is approximately
// constant time if the size of the values used in the compare is consistent
// across calls (from the same line in the calling code).
//  Return Type: int
//      < 0             op1 is less than op2
//      0               op1 is equal to op2
//      > 0             op1 is greater than op2
LIB_EXPORT int ExtMath_UnsignedCmp(const Crypt_Int* op1, const Crypt_Int* op2);

//*** ExtMath_UnsignedCmpWord()
// Compare a Crypt_Int* to a crypt_uword_t.
//  Return Type: int
//      -1              op1 is less that word
//      0               op1 is equal to word
//      1               op1 is greater than word
LIB_EXPORT int ExtMath_UnsignedCmpWord(const Crypt_Int* op1, crypt_uword_t word);

//*** ExtMath_IsEqualWord()
// Compare a Crypt_Int* to a crypt_uword_t for equality
//  Return Type: BOOL
LIB_EXPORT BOOL ExtMath_IsEqualWord(const Crypt_Int* bn, crypt_uword_t word);

//*** ExtMath_IsZero()
// Compare a Crypt_Int* to zero, expected to be O(1) time.
//  Return Type: BOOL
LIB_EXPORT BOOL ExtMath_IsZero(const Crypt_Int* op1);

//*** ExtMath_MostSigBitNum()
//
// This function returns the zero-based number of the MSb (Most significant bit)
// of a Crypt_Int* value.
//
// Return Type: int
//
//      -1              the word was zero or 'bn' was NULL
//      n               the bit number of the most significant bit in the word
LIB_EXPORT int ExtMath_MostSigBitNum(const Crypt_Int* bn);

//*** ExtMath_GetLeastSignificant32bits()
//
// This function returns the least significant 32-bits of an integer value
// Return Type: uint32_t
LIB_EXPORT uint32_t ExtMath_GetLeastSignificant32bits(const Crypt_Int* bn);

//*** ExtMath_SizeInBits()
//
// This function returns the number of bits required to hold a number. It is one
// greater than the Msb.  This function is expected to be side channel safe, and
// may be O(size) or O(1) where 'size' is the allocated (not actual) size of the
// value.
LIB_EXPORT unsigned ExtMath_SizeInBits(const Crypt_Int* n);

// ###############################
// Bitwise Operations
// ###############################

//*** ExtMath_SetBit()
//
// This function will SET a bit in a Crypt_Int*. Bit 0 is the least-significant
// bit in the 0th digit_t. The function returns TRUE if the bitNum is within the
// range valid for the given number.  If bitNum is too large, the function
// should return FALSE, and the TPM will enter failure mode.
// Return Type: BOOL
LIB_EXPORT BOOL ExtMath_SetBit(Crypt_Int*   bn,     // IN/OUT: big number to modify
                               unsigned int bitNum  // IN: Bit number to SET
);

//*** ExtMath_TestBit()
// This function is used to check to see if a bit is SET in a bignum_t. The 0th bit
// is the LSb of d[0].
//  Return Type: BOOL
//      TRUE(1)         the bit is set
//      FALSE(0)        the bit is not set or the number is out of range
LIB_EXPORT BOOL ExtMath_TestBit(Crypt_Int*   bn,     // IN: number to check
                                unsigned int bitNum  // IN: bit to test
);

//***ExtMath_MaskBits()
// This function is used to mask off high order bits of a big number.
// The returned value will have no more than 'maskBit' bits
// set.
// Note: There is a requirement that unused words of a bignum_t are set to zero.
//  Return Type: BOOL
//      TRUE(1)         result masked
//      FALSE(0)        the input was not as large as the mask
LIB_EXPORT BOOL ExtMath_MaskBits(
    Crypt_Int*    bn,      // IN/OUT: number to mask
    crypt_uword_t maskBit  // IN: the bit number for the mask.
);

//*** ExtMath_ShiftRight()
// This function will shift a Crypt_Int* to the right by the shiftAmount.
// This function always returns TRUE.
LIB_EXPORT BOOL ExtMath_ShiftRight(
    Crypt_Int* result, const Crypt_Int* toShift, uint32_t shiftAmount);

// ***************************************************************************
// ECC Functions
// ***************************************************************************
// #################
// type initializers
// #################

//** initialize point structure given memory size of each coordinate
LIB_EXPORT Crypt_Point* ExtEcc_Initialize_Point(Crypt_Point* buffer,
                                                NUMBYTES     bitsPerCoord);

//** ExtEcc_CurveInitialize()
// This function is used to initialize a Crypt_EccCurve structure. The
// structure is a set of pointers to Crypt_Int* values. The curve-dependent values are
// set by a different function. This function is only needed
// if the TPM supports ECC.
LIB_EXPORT const Crypt_EccCurve* ExtEcc_CurveInitialize(Crypt_EccCurve* E,
                                                        TPM_ECC_CURVE   curveId);

// #################
// DESTRUCTOR - See Warning
// #################

//*** ExtEcc_CurveFree()
// This function will free the allocated components of the curve and end the
// frame in which the curve data exists.
// WARNING: Not guaranteed to be called in presence of LONGJMP_SUPPORTED.
LIB_EXPORT void ExtEcc_CurveFree(const Crypt_EccCurve* E);

// #################
// Buffer Converters
// #################
//** point structure to/from raw coordinate buffers.
LIB_EXPORT Crypt_Point* ExtEcc_PointFromBytes(Crypt_Point* buffer,
                                              const BYTE*  x,
                                              NUMBYTES     nBytesX,
                                              const BYTE*  y,
                                              NUMBYTES     nBytesY);

LIB_EXPORT BOOL         ExtEcc_PointToBytes(
            const Crypt_Point* point, BYTE* x, NUMBYTES* nBytesX, BYTE* y, NUMBYTES* nBytesY);

// ####################
// ECC Point Operations
// ####################

//** ExtEcc_PointMultiply()
// This function does a point multiply of the form R = [d]S. A return of FALSE
// indicates that the result was the point at infinity. This function is only needed
// if the TPM supports ECC.
LIB_EXPORT BOOL ExtEcc_PointMultiply(Crypt_Point*          R,
                                     const Crypt_Point*    S,
                                     const Crypt_Int*      d,
                                     const Crypt_EccCurve* E);

//** ExtEcc_PointMultiplyAndAdd()
// This function does a point multiply of the form R = [d]S + [u]Q. A return of
// FALSE indicates that the result was the point at infinity. This function is only
// needed if the TPM supports ECC.
LIB_EXPORT BOOL ExtEcc_PointMultiplyAndAdd(Crypt_Point*          R,
                                           const Crypt_Point*    S,
                                           const Crypt_Int*      d,
                                           const Crypt_Point*    Q,
                                           const Crypt_Int*      u,
                                           const Crypt_EccCurve* E);

//** ExtEcc_PointAdd()
// This function does a point add R = S + Q. A return of FALSE
// indicates that the result was the point at infinity. This function is only needed
// if the TPM supports ECC.
LIB_EXPORT BOOL ExtEcc_PointAdd(Crypt_Point*          R,
                                const Crypt_Point*    S,
                                const Crypt_Point*    Q,
                                const Crypt_EccCurve* E);

// #####################
// ECC Point Information
// #####################
LIB_EXPORT BOOL ExtEcc_IsPointOnCurve(const Crypt_Point* Q, const Crypt_EccCurve* E);
LIB_EXPORT BOOL ExtEcc_IsInfinityPoint(const Crypt_Point* pt);
// extract the X-Coordinate of a point
LIB_EXPORT const Crypt_Int* ExtEcc_PointX(const Crypt_Point* pt);

// extract the Y-Coordinate of a point
// (no current use case for the Y coordinate alone, signatures use X)
// LIB_EXPORT const Crypt_Int* ExtEcc_PointY(const Crypt_Point* pt);

// #####################
// ECC Curve Information
// #####################
// These functions are expected to be fast, returning pre-built constants without
// allocation or copying.
LIB_EXPORT const Crypt_Int*   ExtEcc_CurveGetPrime(TPM_ECC_CURVE curveId);
LIB_EXPORT const Crypt_Int*   ExtEcc_CurveGetOrder(TPM_ECC_CURVE curveId);
LIB_EXPORT const Crypt_Int*   ExtEcc_CurveGetCofactor(TPM_ECC_CURVE curveId);
LIB_EXPORT const Crypt_Int*   ExtEcc_CurveGet_a(TPM_ECC_CURVE curveId);
LIB_EXPORT const Crypt_Int*   ExtEcc_CurveGet_b(TPM_ECC_CURVE curveId);
LIB_EXPORT const Crypt_Point* ExtEcc_CurveGetG(TPM_ECC_CURVE curveId);
LIB_EXPORT const Crypt_Int*   ExtEcc_CurveGetGx(TPM_ECC_CURVE curveId);
LIB_EXPORT const Crypt_Int*   ExtEcc_CurveGetGy(TPM_ECC_CURVE curveId);
LIB_EXPORT TPM_ECC_CURVE      ExtEcc_CurveGetCurveId(const Crypt_EccCurve* E);

#endif
