#include "Tpm.h"
#include "TpmEcc_Signature_ECDSA_fp.h"
#include "TpmMath_Debug_fp.h"
#include "TpmMath_Util_fp.h"

#if ALG_ECC && ALG_ECDSA
//*** TpmEcc_AdjustEcdsaDigest()
// Function to adjust the digest so that it is no larger than the order of the
// curve. This is used for ECDSA sign and verification.
static Crypt_Int* TpmEcc_AdjustEcdsaDigest(
    Crypt_Int*          bnD,     // OUT: the adjusted digest
    const TPM2B_DIGEST* digest,  // IN: digest to adjust
    const Crypt_Int*    max      // IN: value that indicates the maximum
                                 //     number of bits in the results
)
{
    int bitsInMax = ExtMath_SizeInBits(max);
    int shift;
    //
    if(digest == NULL)
        ExtMath_SetWord(bnD, 0);
    else
    {
        ExtMath_IntFromBytes(bnD,
                             digest->t.buffer,
                             (NUMBYTES)MIN(digest->t.size, BITS_TO_BYTES(bitsInMax)));
        shift = ExtMath_SizeInBits(bnD) - bitsInMax;
        if(shift > 0)
            ExtMath_ShiftRight(bnD, bnD, shift);
    }
    return bnD;
}

//*** TpmEcc_SignEcdsa()
// This function implements the ECDSA signing algorithm. The method is described
// in the comments below.
TPM_RC
TpmEcc_SignEcdsa(Crypt_Int*            bnR,   // OUT: 'r' component of the signature
                 Crypt_Int*            bnS,   // OUT: 's' component of the signature
                 const Crypt_EccCurve* E,     // IN: the curve used in the signature
                                              //     process
                 Crypt_Int*          bnD,     // IN: private signing key
                 const TPM2B_DIGEST* digest,  // IN: the digest to sign
                 RAND_STATE*         rand     // IN: used in debug of signing
)
{
    CRYPT_ECC_NUM(bnK);
    CRYPT_ECC_NUM(bnIk);
    CRYPT_INT_VAR(bnE, MAX_ECC_KEY_BITS);
    CRYPT_POINT_VAR(ecR);
    CRYPT_ECC_NUM(bnX);
    const Crypt_Int* order  = ExtEcc_CurveGetOrder(ExtEcc_CurveGetCurveId(E));
    TPM_RC           retVal = TPM_RC_SUCCESS;
    INT32            tries  = 10;
    BOOL             OK     = FALSE;
    //
    pAssert(digest != NULL);
    // The algorithm as described in "Suite B Implementer's Guide to FIPS
    // 186-3(ECDSA)"
    // 1. Use one of the routines in Appendix A.2 to generate (k, k^-1), a
    //    per-message secret number and its inverse modulo n. Since n is prime,
    //    the output will be invalid only if there is a failure in the RBG.
    // 2. Compute the elliptic curve point R = [k]G = (xR, yR) using EC scalar
    //    multiplication (see [Routines]), where G is the base point included in
    //    the set of domain parameters.
    // 3. Compute r = xR mod n. If r = 0, then return to Step 1. 1.
    // 4. Use the selected hash function to compute H = Hash(M).
    // 5. Convert the bit string H to an integer e as described in Appendix B.2.
    // 6. Compute s = (k^-1 *  (e + d *  r)) mod q. If s = 0, return to Step 1.2.
    // 7. Return (r, s).
    // In the code below, q is n (that it, the order of the curve is p)

    do  // This implements the loop at step 6. If s is zero, start over.
    {
        for(; tries > 0; tries--)
        {
            // Step 1 and 2 -- generate an ephemeral key and the modular inverse
            // of the private key.
            if(!TpmEcc_GenerateKeyPair(bnK, ecR, E, rand))
                continue;
            // get mutable copy of X coordinate
            ExtMath_Copy(bnX, ExtEcc_PointX(ecR));
            // x coordinate is mod p.  Make it mod q
            ExtMath_Mod(bnX, order);
            // Make sure that it is not zero;
            if(ExtMath_IsZero(bnX))
                continue;
            // write the modular reduced version of r as part of the signature
            ExtMath_Copy(bnR, bnX);
            // Make sure that a modular inverse exists and try again if not
            OK = (ExtMath_ModInverse(bnIk, bnK, order));
            if(OK)
                break;
        }
        if(!OK)
            goto Exit;

        TpmEcc_AdjustEcdsaDigest(bnE, digest, order);

        // now have inverse of K (bnIk), e (bnE), r (bnR),  d (bnD) and
        // ExtEcc_CurveGetOrder(ExtEcc_CurveGetCurveId(E))
        // Compute s = k^-1 (e + r*d)(mod q)
        //  first do s = r*d mod q
        ExtMath_ModMult(bnS, bnR, bnD, order);
        // s = e + s = e + r * d
        ExtMath_Add(bnS, bnE, bnS);
        // s = k^(-1)s (mod n) = k^(-1)(e + r * d)(mod n)
        ExtMath_ModMult(bnS, bnIk, bnS, order);

        // If S is zero, try again
    } while(ExtMath_IsZero(bnS));
Exit:
    return retVal;
}

//*** TpmEcc_ValidateSignatureEcdsa()
// This function validates an ECDSA signature. rIn and sIn should have been checked
// to make sure that they are in the range 0 < 'v' < 'n'
//  Return Type: TPM_RC
//      TPM_RC_SIGNATURE           signature not valid
TPM_RC
TpmEcc_ValidateSignatureEcdsa(
    Crypt_Int*            bnR,  // IN: 'r' component of the signature
    Crypt_Int*            bnS,  // IN: 's' component of the signature
    const Crypt_EccCurve* E,    // IN: the curve used in the signature
                                //     process
    const Crypt_Point*  ecQ,    // IN: the public point of the key
    const TPM2B_DIGEST* digest  // IN: the digest that was signed
)
{
    // Make sure that the allocation for the digest is big enough for a maximum
    // digest
    CRYPT_INT_VAR(bnE, MAX_ECC_KEY_BITS);
    CRYPT_POINT_VAR(ecR);
    CRYPT_ECC_NUM(bnU1);
    CRYPT_ECC_NUM(bnU2);
    CRYPT_ECC_NUM(bnW);
    CRYPT_ECC_NUM(bnV);
    const Crypt_Int* order  = ExtEcc_CurveGetOrder(ExtEcc_CurveGetCurveId(E));
    TPM_RC           retVal = TPM_RC_SIGNATURE;
    //
    // Get adjusted digest
    TpmEcc_AdjustEcdsaDigest(bnE, digest, order);
    // 1. If r and s are not both integers in the interval [1, n - 1], output
    //    INVALID.
    //  bnR  and bnS were validated by the caller
    // 2. Use the selected hash function to compute H0 = Hash(M0).
    // This is an input parameter
    // 3. Convert the bit string H0 to an integer e as described in Appendix B.2.
    // Done at entry
    // 4. Compute w = (s')^-1 mod n, using the routine in Appendix B.1.
    if(!ExtMath_ModInverse(bnW, bnS, order))
        goto Exit;
    // 5. Compute u1 = (e' *   w) mod n, and compute u2 = (r' *  w) mod n.
    ExtMath_ModMult(bnU1, bnE, bnW, order);
    ExtMath_ModMult(bnU2, bnR, bnW, order);
    // 6. Compute the elliptic curve point R = (xR, yR) = u1G+u2Q, using EC
    //    scalar multiplication and EC addition (see [Routines]). If R is equal to
    //    the point at infinity O, output INVALID.
    if(TpmEcc_PointMult(
           ecR, ExtEcc_CurveGetG(ExtEcc_CurveGetCurveId(E)), bnU1, ecQ, bnU2, E)
       != TPM_RC_SUCCESS)
        goto Exit;
    // 7. Compute v = Rx mod n.
    ExtMath_Copy(bnV, ExtEcc_PointX(ecR));
    ExtMath_Mod(bnV, order);
    // 8. Compare v and r0. If v = r0, output VALID; otherwise, output INVALID
    if(ExtMath_UnsignedCmp(bnV, bnR) != 0)
        goto Exit;

    retVal = TPM_RC_SUCCESS;
Exit:
    return retVal;
}

#endif  // ALG_ECC && ALG_ECDSA
