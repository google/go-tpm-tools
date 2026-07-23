/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar 28, 2019  Time: 08:25:18PM
 */

#ifndef _CRYPT_ECC_SIGNATURE_FP_H_
#define _CRYPT_ECC_SIGNATURE_FP_H_

#if ALG_ECC

//*** CryptEccSign()
// This function is the dispatch function for the various ECC-based
// signing schemes.
// There is a bit of ugliness to the parameter passing. In order to test this,
// we sometime would like to use a deterministic RNG so that we can get the same
// signatures during testing. The easiest way to do this for most schemes is to
// pass in a deterministic RNG and let it return canned values during testing.
// There is a competing need for a canned parameter to use in ECDAA. To accommodate
// both needs with minimal fuss, a special type of RAND_STATE is defined to carry
// the address of the commit value. The setup and handling of this is not very
// different for the caller than what was in previous versions of the code.
//  Return Type: TPM_RC
//      TPM_RC_SCHEME            'scheme' is not supported
LIB_EXPORT TPM_RC CryptEccSign(TPMT_SIGNATURE* signature,  // OUT: signature
                               OBJECT* signKey,  // IN: ECC key to sign the hash
                               const TPM2B_DIGEST* digest,  // IN: digest to sign
                               TPMT_ECC_SCHEME*    scheme,  // IN: signing scheme
                               RAND_STATE*         rand);

//*** CryptEccValidateSignature()
// This function validates an EcDsa or EcSchnorr signature.
// The point 'Qin' needs to have been validated to be on the curve of 'curveId'.
//  Return Type: TPM_RC
//      TPM_RC_SIGNATURE            not a valid signature
LIB_EXPORT TPM_RC CryptEccValidateSignature(
    TPMT_SIGNATURE*     signature,  // IN: signature to be verified
    OBJECT*             signKey,    // IN: ECC key signed the hash
    const TPM2B_DIGEST* digest      // IN: digest that was signed
);

//***CryptEccCommitCompute()
// This function performs the point multiply operations required by TPM2_Commit.
//
// If 'B' or 'M' is provided, they must be on the curve defined by 'curveId'. This
// routine does not check that they are on the curve and results are unpredictable
// if they are not.
//
// It is a fatal error if 'r' is NULL. If 'B' is not NULL, then it is a
// fatal error if 'd' is NULL or if 'K' and 'L' are both NULL.
// If 'M' is not NULL, then it is a fatal error if 'E' is NULL.
//
//  Return Type: TPM_RC
//      TPM_RC_NO_RESULT        if 'K', 'L' or 'E' was computed to be the point
//                              at infinity
//      TPM_RC_CANCELED         a cancel indication was asserted during this
//                              function
LIB_EXPORT TPM_RC CryptEccCommitCompute(
    TPMS_ECC_POINT*      K,        // OUT: [d]B or [r]Q
    TPMS_ECC_POINT*      L,        // OUT: [r]B
    TPMS_ECC_POINT*      E,        // OUT: [r]M
    TPM_ECC_CURVE        curveId,  // IN: the curve for the computations
    TPMS_ECC_POINT*      M,        // IN: M (optional)
    TPMS_ECC_POINT*      B,        // IN: B (optional)
    TPM2B_ECC_PARAMETER* d,        // IN: d (optional)
    TPM2B_ECC_PARAMETER* r         // IN: the computed r value (required)
);
#endif  // ALG_ECC

#endif  // _CRYPT_ECC_SIGNATURE_FP_H_
