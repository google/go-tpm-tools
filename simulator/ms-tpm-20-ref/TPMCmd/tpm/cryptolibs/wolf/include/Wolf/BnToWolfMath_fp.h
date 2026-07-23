/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Aug 30, 2019  Time: 02:11:54PM
 */

#ifndef _TPM_TO_WOLF_MATH_FP_H_
#define _TPM_TO_WOLF_MATH_FP_H_

#ifdef MATH_LIB_WOLF

//*** BnFromWolf()
// This function converts a wolfcrypt mp_int to a TPM bignum. In this implementation
// it is assumed that wolfcrypt used the same format for a big number as does the
// TPM -- an array of native-endian words in little-endian order.
void BnFromWolf(bigNum bn, mp_int* wolfBn);

//*** BnToWolf()
// This function converts a TPM bignum to a wolfcrypt mp_init, and has the same
// assumptions as made by BnFromWolf()
void BnToWolf(mp_int* toInit, bigConst initializer);

//*** MpInitialize()
// This function initializes an wolfcrypt mp_int.
mp_int* MpInitialize(mp_int* toInit);

#  if ALG_ECC

//*** PointFromWolf()
// Function to copy the point result from a wolf ecc_point to a bigNum
void PointFromWolf(bigPoint   pOut,  // OUT: resulting point
                   ecc_point* pIn    // IN: the point to return
);

//*** PointToWolf()
// Function to copy the point result from a bigNum to a wolf ecc_point
void PointToWolf(ecc_point* pOut,  // OUT: resulting point
                 pointConst pIn    // IN: the point to return
);

#  endif  // TPM_ALG_ECC

#endif  // MATH_LIB_WOLF

#endif  // _TPM_TO_WOLF_MATH_FP_H_
