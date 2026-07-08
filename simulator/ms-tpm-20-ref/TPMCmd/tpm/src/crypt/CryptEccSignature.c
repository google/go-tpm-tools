//** Includes and Defines
#include "Tpm.h"
#include "TpmEcc_Signature_ECDSA_fp.h"
#include "TpmEcc_Signature_ECDAA_fp.h"
#include "TpmEcc_Signature_Schnorr_fp.h"
#include "TpmEcc_Signature_SM2_fp.h"
#include "TpmEcc_Util_fp.h"
#include "TpmMath_Util_fp.h"
#include "CryptEccSignature_fp.h"

#if ALG_ECC

//** Utility Functions

//** Signing Functions

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
                               RAND_STATE*         rand)
{
    CRYPT_CURVE_INITIALIZED(E, signKey->publicArea.parameters.eccDetail.curveID);
    CRYPT_ECC_INITIALIZED(bnD, &signKey->sensitive.sensitive.ecc.b);
    CRYPT_ECC_NUM(bnR);
    CRYPT_ECC_NUM(bnS);
    TPM_RC retVal = TPM_RC_SCHEME;
    //
    NOT_REFERENCED(scheme);
    if(E == NULL)
        ERROR_EXIT(TPM_RC_VALUE);
    signature->signature.ecdaa.signatureR.t.size =
        sizeof(signature->signature.ecdaa.signatureR.t.buffer);
    signature->signature.ecdaa.signatureS.t.size =
        sizeof(signature->signature.ecdaa.signatureS.t.buffer);
    TPM_DO_SELF_TEST(signature->sigAlg);
    switch(signature->sigAlg)
    {
        case TPM_ALG_ECDSA:
            retVal = TpmEcc_SignEcdsa(bnR, bnS, E, bnD, digest, rand);
            break;
#  if ALG_ECDAA
        case TPM_ALG_ECDAA:
            retVal = TpmEcc_SignEcdaa(&signature->signature.ecdaa.signatureR,
                                      bnS,
                                      E,
                                      bnD,
                                      digest,
                                      scheme,
                                      signKey,
                                      rand);
            bnR    = NULL;
            break;
#  endif
#  if ALG_ECSCHNORR
        case TPM_ALG_ECSCHNORR:
            retVal = TpmEcc_SignEcSchnorr(
                bnR, bnS, E, bnD, digest, signature->signature.ecschnorr.hash, rand);
            break;
#  endif
#  if ALG_SM2
        case TPM_ALG_SM2:
            retVal = TpmEcc_SignEcSm2(bnR, bnS, E, bnD, digest, rand);
            break;
#  endif
        default:
            break;
    }
    // If signature generation worked, convert the results.
    if(retVal == TPM_RC_SUCCESS)
    {
        NUMBYTES orderBytes = (NUMBYTES)BITS_TO_BYTES(
            ExtMath_SizeInBits(ExtEcc_CurveGetOrder(ExtEcc_CurveGetCurveId(E))));
        if(bnR != NULL)
            TpmMath_IntTo2B(
                bnR, &signature->signature.ecdaa.signatureR.b, orderBytes);
        if(bnS != NULL)
            TpmMath_IntTo2B(
                bnS, &signature->signature.ecdaa.signatureS.b, orderBytes);
    }
Exit:
    CRYPT_CURVE_FREE(E);
    return retVal;
}

//********************* Signature Validation   ********************

//*** CryptEccValidateSignature()
// This function validates an EcDsa or EcSchnorr signature.
// The point 'Qin' needs to have been validated to be on the curve of 'curveId'.
//  Return Type: TPM_RC
//      TPM_RC_SIGNATURE            not a valid signature
LIB_EXPORT TPM_RC CryptEccValidateSignature(
    TPMT_SIGNATURE*     signature,  // IN: signature to be verified
    OBJECT*             signKey,    // IN: ECC key signed the hash
    const TPM2B_DIGEST* digest      // IN: digest that was signed
)
{
    CRYPT_CURVE_INITIALIZED(E, signKey->publicArea.parameters.eccDetail.curveID);
    CRYPT_ECC_NUM(bnR);
    CRYPT_ECC_NUM(bnS);
    CRYPT_POINT_INITIALIZED(ecQ, &signKey->publicArea.unique.ecc);
    const Crypt_Int* order;
    TPM_RC           retVal;

    if(E == NULL)
        ERROR_EXIT(TPM_RC_VALUE);

    order = ExtEcc_CurveGetOrder(ExtEcc_CurveGetCurveId(E));

    //    // Make sure that the scheme is valid
    switch(signature->sigAlg)
    {
        case TPM_ALG_ECDSA:
#  if ALG_ECSCHNORR
        case TPM_ALG_ECSCHNORR:
#  endif
#  if ALG_SM2
        case TPM_ALG_SM2:
#  endif
            break;
        default:
            ERROR_EXIT(TPM_RC_SCHEME);
            break;
    }
    // Can convert r and s after determining that the scheme is an ECC scheme. If
    // this conversion doesn't work, it means that the unmarshaling code for
    // an ECC signature is broken.
    TpmMath_IntFrom2B(bnR, &signature->signature.ecdsa.signatureR.b);
    TpmMath_IntFrom2B(bnS, &signature->signature.ecdsa.signatureS.b);

    // r and s have to be greater than 0 but less than the curve order
    if(ExtMath_IsZero(bnR) || ExtMath_IsZero(bnS))
        ERROR_EXIT(TPM_RC_SIGNATURE);
    if((ExtMath_UnsignedCmp(bnS, order) >= 0)
       || (ExtMath_UnsignedCmp(bnR, order) >= 0))
        ERROR_EXIT(TPM_RC_SIGNATURE);

    switch(signature->sigAlg)
    {
        case TPM_ALG_ECDSA:
            retVal = TpmEcc_ValidateSignatureEcdsa(bnR, bnS, E, ecQ, digest);
            break;

#  if ALG_ECSCHNORR
        case TPM_ALG_ECSCHNORR:
            retVal = TpmEcc_ValidateSignatureEcSchnorr(
                bnR, bnS, signature->signature.any.hashAlg, E, ecQ, digest);
            break;
#  endif
#  if ALG_SM2
        case TPM_ALG_SM2:
            retVal = TpmEcc_ValidateSignatureEcSm2(bnR, bnS, E, ecQ, digest);
            break;
#  endif
        default:
            FAIL_RC(FATAL_ERROR_INTERNAL);
    }
Exit:
    CRYPT_CURVE_FREE(E);
    return retVal;
}

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
)
{
    // Normally initialize E as the curve, but
    // E means something else in this function
    CRYPT_CURVE_INITIALIZED(curve, curveId);
    CRYPT_ECC_INITIALIZED(bnR, r);
    TPM_RC retVal = TPM_RC_SUCCESS;
    //
    // Validate that the required parameters are provided.
    // Note: E has to be provided if computing E := [r]Q or E := [r]M. Will do
    // E := [r]Q if both M and B are NULL.
    pAssert_RC(r != NULL && E != NULL);

    // Initialize the output points in case they are not computed
    ClearPoint2B(K);
    ClearPoint2B(L);
    ClearPoint2B(E);

    // Sizes of the r parameter may not be zero
    pAssert_RC(r->t.size > 0);

    // If B is provided, compute K=[d]B and L=[r]B
    if(B != NULL)
    {
        CRYPT_ECC_INITIALIZED(bnD, d);
        CRYPT_POINT_INITIALIZED(pB, B);
        CRYPT_POINT_VAR(pK);
        CRYPT_POINT_VAR(pL);
        //
        pAssert_RC(d != NULL && K != NULL && L != NULL);

        if(!ExtEcc_IsPointOnCurve(pB, curve))
            ERROR_EXIT(TPM_RC_VALUE);
        // do the math for K = [d]B
        if((retVal = TpmEcc_PointMult(pK, pB, bnD, NULL, NULL, curve))
           != TPM_RC_SUCCESS)
            goto Exit;
        // Convert BN K to TPM2B K
        TpmEcc_PointTo2B(K, pK, curve);
        //  compute L= [r]B after checking for cancel
        if(_plat__IsCanceled())
            ERROR_EXIT(TPM_RC_CANCELED);
        // compute L = [r]B
        if(!TpmEcc_IsValidPrivateEcc(bnR, curve))
            ERROR_EXIT(TPM_RC_VALUE);
        if((retVal = TpmEcc_PointMult(pL, pB, bnR, NULL, NULL, curve))
           != TPM_RC_SUCCESS)
            goto Exit;
        // Convert BN L to TPM2B L
        TpmEcc_PointTo2B(L, pL, curve);
    }
    if((M != NULL) || (B == NULL))
    {
        CRYPT_POINT_INITIALIZED(pM, M);
        CRYPT_POINT_VAR(pE);
        //
        // Make sure that a place was provided for the result
        pAssert_RC(E != NULL);

        // if this is the third point multiply, check for cancel first
        if((B != NULL) && _plat__IsCanceled())
            ERROR_EXIT(TPM_RC_CANCELED);

        // If M provided, then pM will not be NULL and will compute E = [r]M.
        // However, if M was not provided, then pM will be NULL and E = [r]G
        // will be computed
        if((retVal = TpmEcc_PointMult(pE, pM, bnR, NULL, NULL, curve))
           != TPM_RC_SUCCESS)
            goto Exit;
        // Convert E to 2B format
        TpmEcc_PointTo2B(E, pE, curve);
    }
Exit:
    CRYPT_CURVE_FREE(curve);
    return retVal;
}

#endif  // ALG_ECC