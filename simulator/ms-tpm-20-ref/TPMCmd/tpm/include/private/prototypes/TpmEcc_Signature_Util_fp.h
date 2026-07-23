// functions shared by multiple signature algorithms
#ifndef _TPMECC_SIGNATURE_UTIL_FP_H_
#define _TPMECC_SIGNATURE_UTIL_FP_H_

#if ALG_ECC
//*** TpmEcc_SchnorrCalculateS()
// This contains the Schnorr signature (S) computation. It is used by both ECDSA and
// Schnorr signing. The result is computed as: ['s' = 'k' + 'r' * 'd' (mod 'n')]
// where
// 1) 's' is the signature
// 2) 'k' is a random value
// 3) 'r' is the value to sign
// 4) 'd' is the private EC key
// 5) 'n' is the order of the curve
//  Return Type: TPM_RC
//      TPM_RC_NO_RESULT        the result of the operation was zero or 'r' (mod 'n')
//                              is zero
TPM_RC TpmEcc_SchnorrCalculateS(
    Crypt_Int*       bnS,  // OUT: 's' component of the signature
    const Crypt_Int* bnK,  // IN: a random value
    Crypt_Int*       bnR,  // IN: the signature 'r' value
    const Crypt_Int* bnD,  // IN: the private key
    const Crypt_Int* bnN   // IN: the order of the curve
);

#endif  // ALG_ECC
#endif  // _TPMECC_SIGNATURE_UTIL_FP_H_