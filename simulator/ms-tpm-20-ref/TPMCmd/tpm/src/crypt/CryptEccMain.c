//** Includes and Defines
#include "Tpm.h"
#include "TpmMath_Util_fp.h"
#include "TpmEcc_Util_fp.h"
#include "TpmEcc_Signature_ECDSA_fp.h"  // required for pairwise test in key generation

#if ALG_ECC
//** Functions

#  if SIMULATION
void EccSimulationEnd(void)
{
#    if SIMULATION
// put things to be printed at the end of the simulation here
#    endif
}
#  endif  // SIMULATION

//*** CryptEccInit()
// This function is called at _TPM_Init
BOOL CryptEccInit(void)
{
    return TRUE;
}

//*** CryptEccStartup()
// This function is called at TPM2_Startup().
BOOL CryptEccStartup(void)
{
    return TRUE;
}

//*** ClearPoint2B(generic)
// Initialize the size values of a TPMS_ECC_POINT structure.
void ClearPoint2B(TPMS_ECC_POINT* p  // IN: the point
)
{
    if(p != NULL)
    {
        p->x.t.size = 0;
        p->y.t.size = 0;
    }
}

//*** CryptEccGetParametersByCurveId()
// This function returns a pointer to the curve data that is associated with
// the indicated curveId.
// If there is no curve with the indicated ID, the function returns NULL. This
// function is in this module so that it can be called by GetCurve data.
//  Return Type: const TPM_ECC_CURVE_METADATA
//      NULL            curve with the indicated TPM_ECC_CURVE is not implemented
//      != NULL         pointer to the curve data
LIB_EXPORT const TPM_ECC_CURVE_METADATA* CryptEccGetParametersByCurveId(
    TPM_ECC_CURVE curveId  // IN: the curveID
)
{
    int i;
    for(i = 0; i < ECC_CURVE_COUNT; i++)
    {
        if(eccCurves[i].curveId == curveId)
            return &eccCurves[i];
    }
    return NULL;
}

//*** CryptEccGetKeySizeForCurve()
// This function returns the key size in bits of the indicated curve.
LIB_EXPORT UINT16 CryptEccGetKeySizeForCurve(TPM_ECC_CURVE curveId  // IN: the curve
)
{
    const TPM_ECC_CURVE_METADATA* curve = CryptEccGetParametersByCurveId(curveId);
    UINT16                        keySizeInBits;
    //
    keySizeInBits = (curve != NULL) ? curve->keySizeBits : 0;
    return keySizeInBits;
}

//***CryptEccGetOID()
const BYTE* CryptEccGetOID(TPM_ECC_CURVE curveId)
{
    const TPM_ECC_CURVE_METADATA* curve = CryptEccGetParametersByCurveId(curveId);
    return (curve != NULL) ? curve->OID : NULL;
}

//*** CryptEccGetCurveByIndex()
// This function returns the number of the 'i'-th implemented curve. The normal
// use would be to call this function with 'i' starting at 0. When the 'i' is greater
// than or equal to the number of implemented curves, TPM_ECC_NONE is returned.
LIB_EXPORT TPM_ECC_CURVE CryptEccGetCurveByIndex(UINT16 i)
{
    if(i >= ECC_CURVE_COUNT)
        return TPM_ECC_NONE;
    return eccCurves[i].curveId;
}

//*** CryptCapGetECCCurve()
// This function returns the list of implemented ECC curves.
//  Return Type: TPMI_YES_NO
//      YES             if no more ECC curve is available
//      NO              if there are more ECC curves not reported
TPMI_YES_NO
CryptCapGetECCCurve(TPM_ECC_CURVE   curveID,   // IN: the starting ECC curve
                    UINT32          maxCount,  // IN: count of returned curves
                    TPML_ECC_CURVE* curveList  // OUT: ECC curve list
)
{
    TPMI_YES_NO   more = NO;
    UINT16        i;
    UINT32        count = ECC_CURVE_COUNT;
    TPM_ECC_CURVE curve;

    // Initialize output property list
    curveList->count = 0;

    // The maximum count of curves we may return is MAX_ECC_CURVES
    if(maxCount > MAX_ECC_CURVES)
        maxCount = MAX_ECC_CURVES;

    // Scan the eccCurveValues array
    for(i = 0; i < count; i++)
    {
        curve = CryptEccGetCurveByIndex(i);
        // If curveID is less than the starting curveID, skip it
        if(curve < curveID)
            continue;
        if(curveList->count < maxCount)
        {
            // If we have not filled up the return list, add more curves to
            // it
            curveList->eccCurves[curveList->count] = curve;
            curveList->count++;
        }
        else
        {
            // If the return list is full but we still have curves
            // available, report this and stop iterating
            more = YES;
            break;
        }
    }
    return more;
}

//*** CryptCapGetOneECCCurve()
// This function returns whether the ECC curve is implemented.
BOOL CryptCapGetOneECCCurve(TPM_ECC_CURVE curveID  // IN: the  ECC curve
)
{
    UINT16 i;

    // Scan the eccCurveValues array
    for(i = 0; i < ECC_CURVE_COUNT; i++)
    {
        if(CryptEccGetCurveByIndex(i) == curveID)
        {
            return TRUE;
        }
    }
    return FALSE;
}

//*** CryptGetCurveSignScheme()
// This function will return a pointer to the scheme of the curve.
const TPMT_ECC_SCHEME* CryptGetCurveSignScheme(
    TPM_ECC_CURVE curveId  // IN: The curve selector
)
{
    const TPM_ECC_CURVE_METADATA* curve = CryptEccGetParametersByCurveId(curveId);

    if(curve != NULL)
        return &(curve->sign);
    else
        return NULL;
}

//*** CryptGenerateR()
// This function computes the commit random value for a split signing scheme.
//
// If 'c' is NULL, it indicates that 'r' is being generated
// for TPM2_Commit.
// If 'c' is not NULL, the TPM will validate that the 'gr.commitArray'
// bit associated with the input value of 'c' is SET. If not, the TPM
// returns FALSE and no 'r' value is generated.
//  Return Type: BOOL
//      TRUE(1)         r value computed
//      FALSE(0)        no r value computed
BOOL CryptGenerateR(TPM2B_ECC_PARAMETER* r,        // OUT: the generated random value
                    UINT16*              c,        // IN/OUT: count value.
                    TPMI_ECC_CURVE       curveID,  // IN: the curve for the value
                    TPM2B_NAME*          name      // IN: optional name of a key to
                                                   //     associate with 'r'
)
{
    // This holds the marshaled g_commitCounter.
    TPM2B_TYPE(8B, 8);
    TPM2B_8B            cntr = {{8, {0}}};
    UINT32              iterations;
    TPM2B_ECC_PARAMETER n;
    UINT64              currentCount = gr.commitCounter;
    UINT16              t1;
    //
    if(!TpmMath_IntTo2B(ExtEcc_CurveGetOrder(curveID), (TPM2B*)&n, 0))
        return FALSE;

    // If this is the commit phase, use the current value of the commit counter
    if(c != NULL)
    {
        // if the array bit is not set, can't use the value.
        if(!TEST_BIT((*c & COMMIT_INDEX_MASK), gr.commitArray))
            return FALSE;

        // If it is the sign phase, figure out what the counter value was
        // when the commitment was made.
        //
        // When gr.commitArray has less than 64K bits, the extra
        // bits of 'c' are used as a check to make sure that the
        // signing operation is not using an out of range count value
        t1 = (UINT16)currentCount;

        // If the lower bits of c are greater or equal to the lower bits of t1
        // then the upper bits of t1 must be one more than the upper bits
        // of c
        if((*c & COMMIT_INDEX_MASK) >= (t1 & COMMIT_INDEX_MASK))
            // Since the counter is behind, reduce the current count
            currentCount = currentCount - (COMMIT_INDEX_MASK + 1);

        t1 = (UINT16)currentCount;
        if((t1 & ~COMMIT_INDEX_MASK) != (*c & ~COMMIT_INDEX_MASK))
            return FALSE;
        // set the counter to the value that was
        // present when the commitment was made
        currentCount = (currentCount & 0xffffffffffff0000) | *c;
    }
    // Marshal the count value to a TPM2B buffer for the KDF
    cntr.t.size = sizeof(currentCount);
    UINT64_TO_BYTE_ARRAY(currentCount, cntr.t.buffer);

    // Now can do the KDF to create the random value for the signing operation
    // During the creation process, we may generate an r that does not meet the
    // requirements of the random value.
    // want to generate a new r.
    r->t.size = n.t.size;

    for(iterations = 1; iterations < 1000000;)
    {
        int i;
        CryptKDFa(CONTEXT_INTEGRITY_HASH_ALG,
                  &gr.commitNonce.b,
                  COMMIT_STRING,
                  &name->b,
                  &cntr.b,
                  n.t.size * 8,
                  r->t.buffer,
                  &iterations,
                  FALSE);

        // "random" value must be less than the prime
        if(UnsignedCompareB(r->b.size, r->b.buffer, n.t.size, n.t.buffer) >= 0)
            continue;

        // in this implementation it is required that at least bit
        // in the upper half of the number be set
        for(i = n.t.size / 2; i >= 0; i--)
            if(r->b.buffer[i] != 0)
                return TRUE;
    }
    return FALSE;
}

//*** CryptCommit()
// This function is called when the count value is committed. The 'gr.commitArray'
// value associated with the current count value is SET and g_commitCounter is
// incremented. The low-order 16 bits of old value of the counter is returned.
UINT16
CryptCommit(void)
{
    UINT16 oldCount = (UINT16)gr.commitCounter;
    gr.commitCounter++;
    SET_BIT(oldCount & COMMIT_INDEX_MASK, gr.commitArray);
    return oldCount;
}

//*** CryptEndCommit()
// This function is called when the signing operation using the committed value
// is completed. It clears the gr.commitArray bit associated with the count
// value so that it can't be used again.
void CryptEndCommit(UINT16 c  // IN: the counter value of the commitment
)
{
    ClearBit((c & COMMIT_INDEX_MASK), gr.commitArray, sizeof(gr.commitArray));
}

//*** CryptEccGetParameters()
// This function returns the ECC parameter details of the given curve.
//  Return Type: BOOL
//      TRUE(1)         success
//      FALSE(0)        unsupported ECC curve ID
BOOL CryptEccGetParameters(
    TPM_ECC_CURVE              curveId,    // IN: ECC curve ID
    TPMS_ALGORITHM_DETAIL_ECC* parameters  // OUT: ECC parameters
)
{
    const TPM_ECC_CURVE_METADATA* curve = CryptEccGetParametersByCurveId(curveId);
    BOOL                          found = curve != NULL;

    if(found)
    {
        parameters->curveID = curve->curveId;
        parameters->keySize = curve->keySizeBits;
        parameters->kdf     = curve->kdf;
        parameters->sign    = curve->sign;
        //        BnTo2B(data->prime, &parameters->p.b, 0);
        found = found
                && TpmMath_IntTo2B(ExtEcc_CurveGetPrime(curveId),
                                   &parameters->p.b,
                                   parameters->p.t.size);
        found = found
                && TpmMath_IntTo2B(ExtEcc_CurveGet_a(curveId), &parameters->a.b, 0);
        found = found
                && TpmMath_IntTo2B(ExtEcc_CurveGet_b(curveId), &parameters->b.b, 0);
        found = found
                && TpmMath_IntTo2B(ExtEcc_CurveGetGx(curveId),
                                   &parameters->gX.b,
                                   parameters->p.t.size);
        found = found
                && TpmMath_IntTo2B(ExtEcc_CurveGetGy(curveId),
                                   &parameters->gY.b,
                                   parameters->p.t.size);
        //        BnTo2B(data->base.x, &parameters->gX.b, 0);
        //        BnTo2B(data->base.y, &parameters->gY.b, 0);
        found =
            found
            && TpmMath_IntTo2B(ExtEcc_CurveGetOrder(curveId), &parameters->n.b, 0);
        found =
            found
            && TpmMath_IntTo2B(ExtEcc_CurveGetCofactor(curveId), &parameters->h.b, 0);
        // if we got into this IF but failed to get a parameter from the external
        // library, our crypto systems are broken; enter failure mode.
        if(!found)
        {
            FAIL(FATAL_ERROR_MATHLIBRARY);
        }
    }
    return found;
}

//*** TpmEcc_IsValidPrivateEcc()
// Checks that 0 < 'x' < 'q'
BOOL TpmEcc_IsValidPrivateEcc(const Crypt_Int*      x,  // IN: private key to check
                              const Crypt_EccCurve* E   // IN: the curve to check
)
{
    BOOL retVal;
    retVal =
        (!ExtMath_IsZero(x)
         && (ExtMath_UnsignedCmp(x, ExtEcc_CurveGetOrder(ExtEcc_CurveGetCurveId(E)))
             < 0));
    return retVal;
}

LIB_EXPORT BOOL CryptEccIsValidPrivateKey(TPM2B_ECC_PARAMETER* d,
                                          TPM_ECC_CURVE        curveId)
{
    CRYPT_INT_INITIALIZED(bnD, MAX_ECC_PARAMETER_BYTES * 8, d);
    return !ExtMath_IsZero(bnD)
           && (ExtMath_UnsignedCmp(bnD, ExtEcc_CurveGetOrder(curveId)) < 0);
}

//*** TpmEcc_PointMult()
// This function does a point multiply of the form 'R' = ['d']'S' + ['u']'Q' where the
// parameters are Crypt_Int* values. If 'S' is NULL and d is not NULL, then it computes
// 'R' = ['d']'G' + ['u']'Q'  or just 'R' = ['d']'G' if 'u' and 'Q' are NULL.
// If 'skipChecks' is TRUE, then the function will not verify that the inputs are
// correct for the domain. This would be the case when the values were created by the
// CryptoEngine code.
// It will return TPM_RC_NO_RESULT if the resulting point is the point at infinity.
//  Return Type: TPM_RC
//      TPM_RC_NO_RESULT        result of multiplication is a point at infinity
//      TPM_RC_ECC_POINT        'S' or 'Q' is not on the curve
//      TPM_RC_VALUE            'd' or 'u' is not < n
TPM_RC
TpmEcc_PointMult(Crypt_Point*          R,  // OUT: computed point
                 const Crypt_Point*    S,  // IN: optional point to multiply by 'd'
                 const Crypt_Int*      d,  // IN: scalar for [d]S or [d]G
                 const Crypt_Point*    Q,  // IN: optional second point
                 const Crypt_Int*      u,  // IN: optional second scalar
                 const Crypt_EccCurve* E   // IN: curve parameters
)
{
    BOOL OK;
    //
    TPM_DO_SELF_TEST(TPM_ALG_ECDH);

    // Need one scalar
    OK = (d != NULL || u != NULL);

    // If S is present, then d has to be present. If S is not
    // present, then d may or may not be present
    OK = OK && (((S == NULL) == (d == NULL)) || (d != NULL));

    // either both u and Q have to be provided or neither can be provided (don't
    // know what to do if only one is provided.
    OK = OK && ((u == NULL) == (Q == NULL));

    OK = OK && (E != NULL);
    if(!OK)
        return TPM_RC_VALUE;

    OK = (S == NULL) || ExtEcc_IsPointOnCurve(S, E);
    OK = OK && ((Q == NULL) || ExtEcc_IsPointOnCurve(Q, E));
    if(!OK)
        return TPM_RC_ECC_POINT;

    if((d != NULL) && (S == NULL))
        S = ExtEcc_CurveGetG(ExtEcc_CurveGetCurveId(E));
    // If only one scalar, don't need Shamir's trick
    if((d == NULL) || (u == NULL))
    {
        if(d == NULL)
            OK = ExtEcc_PointMultiply(R, Q, u, E);
        else
            OK = ExtEcc_PointMultiply(R, S, d, E);
    }
    else
    {
        OK = ExtEcc_PointMultiplyAndAdd(R, S, d, Q, u, E);
    }
    return (OK ? TPM_RC_SUCCESS : TPM_RC_NO_RESULT);
}

//***TpmEcc_GenPrivateScalar()
// This function gets random values that are the size of the key plus 64 bits. The
// value is reduced (mod ('q' - 1)) and incremented by 1 ('q' is the order of the
// curve. This produces a value ('d') such that 1 <= 'd' < 'q'. This is the method
// of FIPS 186-4 Section B.4.1 ""Key Pair Generation Using Extra Random Bits"".
//  Return Type: BOOL
//      TRUE(1)         success
//      FALSE(0)        failure generating private key
BOOL TpmEcc_GenPrivateScalar(
    Crypt_Int*            dOut,  // OUT: the qualified random value
    const Crypt_EccCurve* E,     // IN: curve for which the private key
                                 //     needs to be appropriate
    RAND_STATE* rand             // IN: state for DRBG
)
{
    TPM_ECC_CURVE    curveId = ExtEcc_CurveGetCurveId(E);
    const Crypt_Int* order   = ExtEcc_CurveGetOrder(curveId);
    BOOL             OK;
    UINT32           orderBits  = ExtMath_SizeInBits(order);
    UINT32           orderBytes = BITS_TO_BYTES(orderBits);
    CRYPT_INT_VAR(bnExtraBits, MAX_ECC_KEY_BITS + 64);
    CRYPT_INT_VAR(nMinus1, MAX_ECC_KEY_BITS);
    //
    OK = TpmMath_GetRandomInteger(bnExtraBits, (orderBytes * 8) + 64, rand);
    OK = OK && ExtMath_SubtractWord(nMinus1, order, 1);
    OK = OK && ExtMath_Mod(bnExtraBits, nMinus1);
    OK = OK && ExtMath_AddWord(dOut, bnExtraBits, 1);

    return OK && !_plat__InFailureMode();
}

//*** TpmEcc_GenerateKeyPair()
// This function gets a private scalar from the source of random bits and does
// the point multiply to get the public key.
BOOL TpmEcc_GenerateKeyPair(Crypt_Int*            bnD,  // OUT: private scalar
                            Crypt_Point*          ecQ,  // OUT: public point
                            const Crypt_EccCurve* E,    // IN: curve for the point
                            RAND_STATE*           rand  // IN: DRBG state to use
)
{
    BOOL OK = FALSE;
    // Get a private scalar
    OK = TpmEcc_GenPrivateScalar(bnD, E, rand);

    // Do a point multiply
    OK = OK && ExtEcc_PointMultiply(ecQ, NULL, bnD, E);

    return OK;
}

//***CryptEccNewKeyPair(***)
// This function creates an ephemeral ECC. It is ephemeral in that
// is expected that the private part of the key will be discarded
LIB_EXPORT TPM_RC CryptEccNewKeyPair(
    TPMS_ECC_POINT*      Qout,    // OUT: the public point
    TPM2B_ECC_PARAMETER* dOut,    // OUT: the private scalar
    TPM_ECC_CURVE        curveId  // IN: the curve for the key
)
{
    CRYPT_CURVE_INITIALIZED(E, curveId);
    CRYPT_POINT_VAR(ecQ);
    CRYPT_ECC_NUM(bnD);
    BOOL OK;

    if(E == NULL)
        return TPM_RC_CURVE;

    TPM_DO_SELF_TEST(TPM_ALG_ECDH);
    OK = TpmEcc_GenerateKeyPair(bnD, ecQ, E, NULL);
    if(OK)
    {
        TpmEcc_PointTo2B(Qout, ecQ, E);
        TpmMath_IntTo2B(bnD, &dOut->b, Qout->x.t.size);
    }
    else
    {
        Qout->x.t.size = Qout->y.t.size = dOut->t.size = 0;
    }
    CRYPT_CURVE_FREE(E);
    return OK ? TPM_RC_SUCCESS : TPM_RC_NO_RESULT;
}

//*** CryptEccPointMultiply()
// This function computes 'R' := ['dIn']'G' + ['uIn']'QIn'. Where 'dIn' and
// 'uIn' are scalars, 'G' and 'QIn' are points on the specified curve and 'G' is the
// default generator of the curve.
//
// The 'xOut' and 'yOut' parameters are optional and may be set to NULL if not
// used.
//
// It is not necessary to provide 'uIn' if 'QIn' is specified but one of 'uIn' and
// 'dIn' must be provided. If 'dIn' and 'QIn' are specified but 'uIn' is not
// provided, then 'R' = ['dIn']'QIn'.
//
// If the multiply produces the point at infinity, the TPM_RC_NO_RESULT is returned.
//
// The sizes of 'xOut' and yOut' will be set to be the size of the degree of
// the curve
//
// It is a fatal error if 'dIn' and 'uIn' are both unspecified (NULL) or if 'Qin'
// or 'Rout' is unspecified.
//
//  Return Type: TPM_RC
//      TPM_RC_ECC_POINT         the point 'Pin' or 'Qin' is not on the curve
//      TPM_RC_NO_RESULT         the product point is at infinity
//      TPM_RC_CURVE             bad curve
//      TPM_RC_VALUE             'dIn' or 'uIn' out of range
//
LIB_EXPORT TPM_RC CryptEccPointMultiply(
    TPMS_ECC_POINT*      Rout,     // OUT: the product point R
    TPM_ECC_CURVE        curveId,  // IN: the curve to use
    TPMS_ECC_POINT*      Pin,      // IN: first point (can be null)
    TPM2B_ECC_PARAMETER* dIn,      // IN: scalar value for [dIn]Qin
                                   //     the Pin
    TPMS_ECC_POINT*      Qin,      // IN: point Q
    TPM2B_ECC_PARAMETER* uIn       // IN: scalar value for the multiplier
                                   //     of Q
)
{
    CRYPT_CURVE_INITIALIZED(E, curveId);
    CRYPT_POINT_INITIALIZED(ecP, Pin);
    CRYPT_ECC_INITIALIZED(bnD, dIn);  // If dIn is null, then bnD is null
    CRYPT_ECC_INITIALIZED(bnU, uIn);
    CRYPT_POINT_INITIALIZED(ecQ, Qin);
    CRYPT_POINT_VAR(ecR);
    TPM_RC retVal;
    //
    retVal = TpmEcc_PointMult(ecR, ecP, bnD, ecQ, bnU, E);

    if(retVal == TPM_RC_SUCCESS)
        TpmEcc_PointTo2B(Rout, ecR, E);
    else
        ClearPoint2B(Rout);

    CRYPT_CURVE_FREE(E);
    return retVal;
}

//*** CryptEccIsPointOnCurve()
// This function is used to test if a point is on a defined curve. It does this
// by checking that 'y'^2 mod 'p' = 'x'^3 + 'a'*'x' + 'b' mod 'p'.
//
// It is a fatal error if 'Q' is not specified (is NULL).
//  Return Type: BOOL
//      TRUE(1)         point is on curve
//      FALSE(0)        point is not on curve or curve is not supported
LIB_EXPORT BOOL CryptEccIsPointOnCurve(
    TPM_ECC_CURVE   curveId,  // IN: the curve selector
    TPMS_ECC_POINT* Qin       // IN: the point.
)
{
    CRYPT_CURVE_INITIALIZED(E, curveId);
    CRYPT_POINT_INITIALIZED(ecQ, Qin);
    BOOL OK;
    //
    pAssert_BOOL(Qin != NULL);
    OK = (E != NULL && (ExtEcc_IsPointOnCurve(ecQ, E)));
    return OK;
}

//*** CryptEccGenerateKey()
// This function generates an ECC key pair based on the input parameters.
// This routine uses KDFa to produce candidate numbers. The method is according
// to FIPS 186-3, section B.1.2 "Key Pair Generation by Testing Candidates."
// According to the method in FIPS 186-3, the resulting private value 'd' should be
// 1 <= 'd' < 'n' where 'n' is the order of the base point.
//
// It is a fatal error if 'Qout', 'dOut', is not provided (is NULL).
//
// If the curve is not supported
// If 'seed' is not provided, then a random number will be used for the key
//  Return Type: TPM_RC
//      TPM_RC_CURVE            curve is not supported
//      TPM_RC_NO_RESULT        could not verify key with signature (FIPS only)
LIB_EXPORT TPM_RC CryptEccGenerateKey(
    TPMT_PUBLIC* publicArea,    // IN/OUT: The public area template for
                                //      the new key. The public key
                                //      area will be replaced computed
                                //      ECC public key
    TPMT_SENSITIVE* sensitive,  // OUT: the sensitive area will be
                                //      updated to contain the private
                                //      ECC key and the symmetric
                                //      encryption key
    RAND_STATE* rand            // IN: if not NULL, the deterministic
                                //     RNG state
)
{
    CRYPT_CURVE_INITIALIZED(E, publicArea->parameters.eccDetail.curveID);
    CRYPT_ECC_NUM(bnD);
    CRYPT_POINT_VAR(ecQ);
    BOOL   OK;
    TPM_RC retVal;
    //
    TPM_DO_SELF_TEST(TPM_ALG_ECDSA);  // ECDSA is used to verify each key

    // Validate parameters
    if(E == NULL)
        ERROR_EXIT(TPM_RC_CURVE);

    publicArea->unique.ecc.x.t.size = 0;
    publicArea->unique.ecc.y.t.size = 0;
    sensitive->sensitive.ecc.t.size = 0;

    OK                              = TpmEcc_GenerateKeyPair(bnD, ecQ, E, rand);
    if(OK)
    {
        TpmEcc_PointTo2B(&publicArea->unique.ecc, ecQ, E);
        TpmMath_IntTo2B(
            bnD, &sensitive->sensitive.ecc.b, publicArea->unique.ecc.x.t.size);
    }
#  if FIPS_COMPLIANT
    // See if PWCT is required
    if(OK && IS_ATTRIBUTE(publicArea->objectAttributes, TPMA_OBJECT, sign))
    {
        CRYPT_ECC_NUM(bnT);
        CRYPT_ECC_NUM(bnS);
        TPM2B_DIGEST digest;
        //
        TPM_DO_SELF_TEST(TPM_ALG_ECDSA);
        digest.t.size = MIN(sensitive->sensitive.ecc.t.size, sizeof(digest.t.buffer));
        // Get a random value to sign using the built in DRBG state
        DRBG_Generate(NULL, digest.t.buffer, digest.t.size);
        if(_plat__InFailureMode())
            return TPM_RC_FAILURE;
        TpmEcc_SignEcdsa(bnT, bnS, E, bnD, &digest, NULL);
        // and make sure that we can validate the signature
        OK = TpmEcc_ValidateSignatureEcdsa(bnT, bnS, E, ecQ, &digest)
             == TPM_RC_SUCCESS;
    }
#  endif
    retVal = (OK) ? TPM_RC_SUCCESS : TPM_RC_NO_RESULT;
Exit:
    CRYPT_CURVE_FREE(E);
    return retVal;
}

#endif  // ALG_ECC