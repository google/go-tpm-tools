// functions shared by multiple signature algorithms
#include "Tpm.h"
#include "TpmEcc_Signature_Util_fp.h"
#include "TpmMath_Debug_fp.h"
#include "TpmMath_Util_fp.h"

#if (ALG_ECC && (ALG_ECSCHNORR || ALG_ECDAA))

//*** TpmEcc_SchnorrCalculateS()
// This contains the Schnorr signature (S) computation. It is used by both ECDAA and
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
)
{
    // Need a local temp value to store the intermediate computation because product
    // size can be larger than will fit in bnS.
    CRYPT_INT_VAR(bnT1, MAX_ECC_PARAMETER_BYTES * 2 * 8);
    //
    // Reduce bnR without changing the input value
    ExtMath_Divide(NULL, bnT1, bnR, bnN);
    if(ExtMath_IsZero(bnT1))
        return TPM_RC_NO_RESULT;
    // compute s = (k + r * d)(mod n)
    // r * d
    ExtMath_Multiply(bnT1, bnT1, bnD);
    // k + r * d
    ExtMath_Add(bnT1, bnT1, bnK);
    // k + r * d (mod n)
    ExtMath_Divide(NULL, bnS, bnT1, bnN);
    return (ExtMath_IsZero(bnS)) ? TPM_RC_NO_RESULT : TPM_RC_SUCCESS;
}

#endif  // (ALG_ECC && (ALG_ECSCHNORR || ALG_ECDAA))
