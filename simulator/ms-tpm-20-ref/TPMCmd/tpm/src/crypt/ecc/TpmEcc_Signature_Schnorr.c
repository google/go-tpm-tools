#include "Tpm.h"
#include "TpmEcc_Signature_Schnorr_fp.h"
#include "TpmEcc_Signature_Util_fp.h"
#include "TpmMath_Debug_fp.h"
#include "TpmMath_Util_fp.h"

#if ALG_ECC && ALG_ECSCHNORR

//*** SchnorrReduce()
// Function to reduce a hash result if it's magnitude is too large. The size of
// 'number' is set so that it has no more bytes of significance than 'reference'
// value. If the resulting number can have more bits of significance than
// 'reference'.
static void SchnorrReduce(TPM2B*           number,    // IN/OUT: Value to reduce
                          const Crypt_Int* reference  // IN: the reference value
)
{
    UINT16 maxBytes = (UINT16)BITS_TO_BYTES(ExtMath_SizeInBits(reference));
    if(number->size > maxBytes)
        number->size = maxBytes;
}

//*** SchnorrEcc()
// This function is used to perform a modified Schnorr signature.
//
// This function will generate a random value 'k' and compute
// a) ('xR', 'yR') = ['k']'G'
// b) 'r' = "Hash"('xR' || 'P')(mod 'q')
// c) 'rT' = truncated 'r'
// d) 's'= 'k' + 'rT' * 'ds' (mod 'q')
// e) return the tuple 'rT', 's'
//
//  Return Type: TPM_RC
//      TPM_RC_NO_RESULT        failure in the Schnorr sign process
//      TPM_RC_SCHEME           hashAlg can't produce zero-length digest
TPM_RC TpmEcc_SignEcSchnorr(
    Crypt_Int*            bnR,      // OUT: 'r' component of the signature
    Crypt_Int*            bnS,      // OUT: 's' component of the signature
    const Crypt_EccCurve* E,        // IN: the curve used in signing
    Crypt_Int*            bnD,      // IN: the signing key
    const TPM2B_DIGEST*   digest,   // IN: the digest to sign
    TPM_ALG_ID            hashAlg,  // IN: signing scheme (contains a hash)
    RAND_STATE*           rand      // IN: non-NULL when testing
)
{
    HASH_STATE hashState;
    UINT16     digestSize = CryptHashGetDigestSize(hashAlg);
    TPM2B_TYPE(T, MAX(MAX_DIGEST_SIZE, MAX_ECC_KEY_BYTES));
    TPM2B_T          T2b;
    TPM2B*           e      = &T2b.b;
    TPM_RC           retVal = TPM_RC_NO_RESULT;
    const Crypt_Int* order;
    const Crypt_Int* prime;
    CRYPT_ECC_NUM(bnK);
    CRYPT_POINT_VAR(ecR);
    //
    // Parameter checks
    if(E == NULL)
        ERROR_EXIT(TPM_RC_VALUE);

    order = ExtEcc_CurveGetOrder(ExtEcc_CurveGetCurveId(E));
    prime = ExtEcc_CurveGetOrder(ExtEcc_CurveGetCurveId(E));

    // If the digest does not produce a hash, then null the signature and return
    // a failure.
    if(digestSize == 0)
    {
        ExtMath_SetWord(bnR, 0);
        ExtMath_SetWord(bnS, 0);
        ERROR_EXIT(TPM_RC_SCHEME);
    }
    do
    {
        // Generate a random key pair
        if(!TpmEcc_GenerateKeyPair(bnK, ecR, E, rand))
            break;
        // Convert R.x to a string
        TpmMath_IntTo2B(ExtEcc_PointX(ecR),
                        e,
                        (NUMBYTES)BITS_TO_BYTES(ExtMath_SizeInBits(prime)));

        // f) compute r = Hash(e || P) (mod n)
        CryptHashStart(&hashState, hashAlg);
        CryptDigestUpdate2B(&hashState, e);
        CryptDigestUpdate2B(&hashState, &digest->b);
        e->size = CryptHashEnd(&hashState, digestSize, e->buffer);
        // Reduce the hash size if it is larger than the curve order
        SchnorrReduce(e, order);
        // Convert hash to number
        TpmMath_IntFrom2B(bnR, e);
        // Do the Schnorr computation
        retVal = TpmEcc_SchnorrCalculateS(
            bnS, bnK, bnR, bnD, ExtEcc_CurveGetOrder(ExtEcc_CurveGetCurveId(E)));
    } while(retVal == TPM_RC_NO_RESULT);
Exit:
    return retVal;
}

//*** TpmEcc_ValidateSignatureEcSchnorr()
// This function is used to validate an EC Schnorr signature.
//  Return Type: TPM_RC
//      TPM_RC_SIGNATURE        signature not valid
TPM_RC TpmEcc_ValidateSignatureEcSchnorr(
    Crypt_Int*            bnR,      // IN: 'r' component of the signature
    Crypt_Int*            bnS,      // IN: 's' component of the signature
    TPM_ALG_ID            hashAlg,  // IN: hash algorithm of the signature
    const Crypt_EccCurve* E,        // IN: the curve used in the signature
                                    //     process
    Crypt_Point*        ecQ,        // IN: the public point of the key
    const TPM2B_DIGEST* digest      // IN: the digest that was signed
)
{
    CRYPT_INT_MAX(bnRn);
    CRYPT_POINT_VAR(ecE);
    CRYPT_INT_MAX(bnEx);
    const Crypt_Int* order      = ExtEcc_CurveGetOrder(ExtEcc_CurveGetCurveId(E));
    UINT16           digestSize = CryptHashGetDigestSize(hashAlg);
    HASH_STATE       hashState;
    TPM2B_TYPE(BUFFER, MAX(MAX_ECC_PARAMETER_BYTES, MAX_DIGEST_SIZE));
    TPM2B_BUFFER Ex2 = {{sizeof(Ex2.t.buffer), {0}}};
    BOOL         OK;
    //
    // E = [s]G - [r]Q
    ExtMath_Mod(bnR, order);
    // Make -r = n - r
    ExtMath_Subtract(bnRn, order, bnR);
    // E = [s]G + [-r]Q
    OK = TpmEcc_PointMult(
             ecE, ExtEcc_CurveGetG(ExtEcc_CurveGetCurveId(E)), bnS, ecQ, bnRn, E)
         == TPM_RC_SUCCESS;
    //   // reduce the x portion of E mod q
    //    OK = OK && ExtMath_Mod(ecE->x, order);
    // Convert to byte string
    OK = OK
         && TpmMath_IntTo2B(ExtEcc_PointX(ecE),
                            &Ex2.b,
                            (NUMBYTES)(BITS_TO_BYTES(ExtMath_SizeInBits(order))));
    if(OK)
    {
        // Ex = h(pE.x || digest)
        CryptHashStart(&hashState, hashAlg);
        CryptDigestUpdate(&hashState, Ex2.t.size, Ex2.t.buffer);
        CryptDigestUpdate(&hashState, digest->t.size, digest->t.buffer);
        Ex2.t.size = CryptHashEnd(&hashState, digestSize, Ex2.t.buffer);
        SchnorrReduce(&Ex2.b, order);
        TpmMath_IntFrom2B(bnEx, &Ex2.b);
        // see if Ex matches R
        OK = ExtMath_UnsignedCmp(bnEx, bnR) == 0;
    }
    return (OK) ? TPM_RC_SUCCESS : TPM_RC_SIGNATURE;
}

#endif  // ALG_ECC && ALG_ECSCHNORR
