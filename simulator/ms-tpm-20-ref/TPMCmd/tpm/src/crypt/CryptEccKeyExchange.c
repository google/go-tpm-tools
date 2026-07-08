//** Introduction
// This file contains the functions that are used for the two-phase, ECC,
// key-exchange protocols

#include "Tpm.h"
#include "TpmMath_Util_fp.h"
#include "TpmEcc_Util_fp.h"

#if CC_ZGen_2Phase == YES

//** Functions

#  if ALG_ECMQV

//*** avf1()
// This function does the associated value computation required by MQV key
// exchange.
// Process:
// 1. Convert 'xQ' to an integer 'xqi' using the convention specified in Appendix C.3.
// 2. Calculate
//        xqm = xqi mod 2^ceil(f/2) (where f = ceil(log2(n)).
// 3. Calculate the associate value function
//        avf(Q) = xqm + 2ceil(f / 2)
// Always returns TRUE(1).
static BOOL avf1(Crypt_Int* bnX,  // IN/OUT: the reduced value
                 Crypt_Int* bnN   // IN: the order of the curve
)
{
    // compute f = 2^(ceil(ceil(log2(n)) / 2))
    int f = (ExtMath_SizeInBits(bnN) + 1) / 2;
    // x' = 2^f + (x mod 2^f)
    ExtMath_MaskBits(bnX, f);  // This is mod 2*2^f but it doesn't matter because
    // the next operation will SET the extra bit anyway
    if(!ExtMath_SetBit(bnX, f))
    {
        FAIL(FATAL_ERROR_CRYPTO);
    }
    return TRUE;
}

//*** C_2_2_MQV()
// This function performs the key exchange defined in SP800-56A
// 6.1.1.4 Full MQV, C(2, 2, ECC MQV).
//
// CAUTION: Implementation of this function may require use of essential claims in
// patents not owned by TCG members.
//
// Points 'QsB' and 'QeB' are required to be on the curve of 'inQsA'. The function
// will fail, possibly catastrophically, if this is not the case.
//  Return Type: TPM_RC
//      TPM_RC_NO_RESULT        the value for dsA does not give a valid point on the
//                              curve
static TPM_RC C_2_2_MQV(TPMS_ECC_POINT* outZ,   // OUT: the computed point
                        TPM_ECC_CURVE curveId,  // IN: the curve for the computations
                        TPM2B_ECC_PARAMETER* dsA,  // IN: static private TPM key
                        TPM2B_ECC_PARAMETER* deA,  // IN: ephemeral private TPM key
                        TPMS_ECC_POINT*      QsB,  // IN: static public party B key
                        TPMS_ECC_POINT*      QeB   // IN: ephemeral public party B key
)
{
    CRYPT_CURVE_INITIALIZED(E, curveId);
    CRYPT_POINT_VAR(pQeA);
    CRYPT_POINT_INITIALIZED(pQeB, QeB);
    CRYPT_POINT_INITIALIZED(pQsB, QsB);
    CRYPT_ECC_NUM(bnTa);
    CRYPT_ECC_INITIALIZED(bnDeA, deA);
    CRYPT_ECC_INITIALIZED(bnDsA, dsA);
    CRYPT_ECC_NUM(bnN);
    CRYPT_ECC_NUM(bnXeB);
    TPM_RC retVal;
    //
    // Parameter checks
    if(E == NULL)
        ERROR_EXIT(TPM_RC_VALUE);
    pAssert_RC(
        outZ != NULL && pQeB != NULL && pQsB != NULL && deA != NULL && dsA != NULL);
    // Process:
    //  1. implicitsigA = (de,A + avf(Qe,A)ds,A ) mod n.
    //  2. P = h(implicitsigA)(Qe,B + avf(Qe,B)Qs,B).
    //  3. If P = O, output an error indicator.
    //  4. Z=xP, where xP is the x-coordinate of P.

    // Compute the public ephemeral key pQeA = [de,A]G
    if((retVal =
            TpmEcc_PointMult(pQeA, ExtEcc_CurveGetG(curveId), bnDeA, NULL, NULL, E))
       != TPM_RC_SUCCESS)
        goto Exit;

    //  1. implicitsigA = (de,A + avf(Qe,A)ds,A ) mod n.
    //  tA := (ds,A + de,A  avf(Xe,A)) mod n    (3)
    //  Compute 'tA' = ('deA' +  'dsA'  avf('XeA')) mod n
    // Ta = avf(XeA);
    ExtMath_Copy(bnTa, ExtEcc_PointX(pQeA));
    avf1(bnTa, bnN);
    // do Ta = ds,A * Ta mod n = dsA * avf(XeA) mod n
    ExtMath_ModMult(bnTa, bnDsA, bnTa, bnN);
    // now Ta = deA + Ta mod n =  deA + dsA * avf(XeA) mod n
    ExtMath_Add(bnTa, bnTa, bnDeA);
    ExtMath_Mod(bnTa, bnN);

    //  2. P = h(implicitsigA)(Qe,B + avf(Qe,B)Qs,B).
    // Put this in because almost every case of h is == 1 so skip the call when
    // not necessary.
    if(!ExtMath_IsEqualWord(ExtEcc_CurveGetCofactor(curveId), 1))
        // Cofactor is not 1 so compute Ta := Ta * h mod n
        ExtMath_ModMult(bnTa,
                        bnTa,
                        ExtEcc_CurveGetCofactor(curveId),
                        ExtEcc_CurveGetOrder(curveId));

    // Now that 'tA' is (h * 'tA' mod n)
    // 'outZ' = (tA)(Qe,B + avf(Qe,B)Qs,B).

    // first, compute XeB = avf(XeB)
    avf1(bnXeB, bnN);

    // QsB := [XeB]QsB
    TpmEcc_PointMult(pQsB, pQsB, bnXeB, NULL, NULL, E);
    ExtEcc_PointAdd(pQeB, pQeB, pQsB, E);

    // QeB := [tA]QeB = [tA](QsB + [Xe,B]QeB) and check for at infinity
    // If the result is not the point at infinity, return QeB
    TpmEcc_PointMult(pQeB, pQeB, bnTa, NULL, NULL, E);
    if(ExtEcc_IsInfinityPoint(pQeB))
        ERROR_EXIT(TPM_RC_NO_RESULT);
    // Convert Crypt_Int* E to TPM2B E
    TpmEcc_PointTo2B(outZ, pQeB, E);

Exit:
    CRYPT_CURVE_FREE(E);
    return retVal;
}

#  endif  // ALG_ECMQV

//*** C_2_2_ECDH()
// This function performs the two phase key exchange defined in SP800-56A,
// 6.1.1.2 Full Unified Model, C(2, 2, ECC CDH).
//
static TPM_RC C_2_2_ECDH(TPMS_ECC_POINT* outZs,  // OUT: Zs
                         TPMS_ECC_POINT* outZe,  // OUT: Ze
                         TPM_ECC_CURVE curveId,  // IN: the curve for the computations
                         TPM2B_ECC_PARAMETER* dsA,  // IN: static private TPM key
                         TPM2B_ECC_PARAMETER* deA,  // IN: ephemeral private TPM key
                         TPMS_ECC_POINT*      QsB,  // IN: static public party B key
                         TPMS_ECC_POINT*      QeB  // IN: ephemeral public party B key
)
{
    CRYPT_CURVE_INITIALIZED(E, curveId);
    CRYPT_ECC_INITIALIZED(bnAs, dsA);
    CRYPT_ECC_INITIALIZED(bnAe, deA);
    CRYPT_POINT_INITIALIZED(ecBs, QsB);
    CRYPT_POINT_INITIALIZED(ecBe, QeB);
    CRYPT_POINT_VAR(ecZ);
    TPM_RC retVal;
    //
    // Parameter checks
    if(E == NULL)
        ERROR_EXIT(TPM_RC_CURVE);
    pAssert_RC(
        outZs != NULL && dsA != NULL && deA != NULL && QsB != NULL && QeB != NULL);

    // Do the point multiply for the Zs value ([dsA]QsB)
    retVal = TpmEcc_PointMult(ecZ, ecBs, bnAs, NULL, NULL, E);
    if(retVal == TPM_RC_SUCCESS)
    {
        // Convert the Zs value.
        TpmEcc_PointTo2B(outZs, ecZ, E);
        // Do the point multiply for the Ze value ([deA]QeB)
        retVal = TpmEcc_PointMult(ecZ, ecBe, bnAe, NULL, NULL, E);
        if(retVal == TPM_RC_SUCCESS)
            TpmEcc_PointTo2B(outZe, ecZ, E);
    }
Exit:
    CRYPT_CURVE_FREE(E);
    return retVal;
}

//*** CryptEcc2PhaseKeyExchange()
// This function is the dispatch routine for the EC key exchange functions that use
// two ephemeral and two static keys.
//  Return Type: TPM_RC
//      TPM_RC_SCHEME             scheme is not defined
LIB_EXPORT TPM_RC CryptEcc2PhaseKeyExchange(
    TPMS_ECC_POINT*      outZ1,    // OUT: a computed point
    TPMS_ECC_POINT*      outZ2,    // OUT: and optional second point
    TPM_ECC_CURVE        curveId,  // IN: the curve for the computations
    TPM_ALG_ID           scheme,   // IN: the key exchange scheme
    TPM2B_ECC_PARAMETER* dsA,      // IN: static private TPM key
    TPM2B_ECC_PARAMETER* deA,      // IN: ephemeral private TPM key
    TPMS_ECC_POINT*      QsB,      // IN: static public party B key
    TPMS_ECC_POINT*      QeB       // IN: ephemeral public party B key
)
{
    pAssert_RC(
        outZ1 != NULL && dsA != NULL && deA != NULL && QsB != NULL && QeB != NULL);

    // Initialize the output points so that they are empty until one of the
    // functions decides otherwise
    outZ1->x.b.size = 0;
    outZ1->y.b.size = 0;
    if(outZ2 != NULL)
    {
        outZ2->x.b.size = 0;
        outZ2->y.b.size = 0;
    }
    switch(scheme)
    {
        case TPM_ALG_ECDH:
            return C_2_2_ECDH(outZ1, outZ2, curveId, dsA, deA, QsB, QeB);
            break;
#  if ALG_ECMQV
        case TPM_ALG_ECMQV:
            return C_2_2_MQV(outZ1, curveId, dsA, deA, QsB, QeB);
            break;
#  endif
#  if ALG_SM2
        case TPM_ALG_SM2:
            return SM2KeyExchange(outZ1, curveId, dsA, deA, QsB, QeB);
            break;
#  endif
        default:
            return TPM_RC_SCHEME;
    }
}

#  if ALG_SM2

//*** ComputeWForSM2()
// Compute the value for w used by SM2
static UINT32 ComputeWForSM2(TPM_ECC_CURVE curveId)
{
    //  w := ceil(ceil(log2(n)) / 2) - 1
    return (ExtMath_MostSigBitNum(ExtEcc_CurveGetOrder(curveId)) / 2 - 1);
}

//*** avfSm2()
// This function does the associated value computation required by SM2 key
// exchange. This is different from the avf() in the international standards
// because it returns a value that is half the size of the value returned by the
// standard avf(). For example, if 'n' is 15, 'Ws' ('w' in the standard) is 2 but
// the 'W' here is 1. This means that an input value of 14 (1110b) would return a
// value of 110b with the standard but 10b with the scheme in SM2.
static Crypt_Int* avfSm2(Crypt_Int* bn,  // IN/OUT: the reduced value
                         UINT32     w    // IN: the value of w
)
{
    // a)   set w := ceil(ceil(log2(n)) / 2) - 1
    // b)   set x' := 2^w + ( x & (2^w - 1))
    // This is just like the avf for MQV where x' = 2^w + (x mod 2^w)

    ExtMath_MaskBits(bn, w);  // as with avf1, this is too big by a factor of 2 but
                              // it doesn't matter because we SET the extra bit
                              // anyway
    if(!ExtMath_SetBit(bn, w))
    {
        FAIL(FATAL_ERROR_CRYPTO);
    }
    return bn;
}

//*** SM2KeyExchange()
// This function performs the key exchange defined in SM2.
// The first step is to compute
//  'tA' = ('dsA' + 'deA'  avf(Xe,A)) mod 'n'
// Then, compute the 'Z' value from
// 'outZ' = ('h'  'tA' mod 'n') ('QsA' + [avf('QeB.x')]('QeB')).
// The function will compute the ephemeral public key from the ephemeral
// private key.
// All points are required to be on the curve of 'inQsA'. The function will fail
// catastrophically if this is not the case
//  Return Type: TPM_RC
//      TPM_RC_NO_RESULT        the value for dsA does not give a valid point on the
//                              curve
LIB_EXPORT TPM_RC SM2KeyExchange(
    TPMS_ECC_POINT*      outZ,     // OUT: the computed point
    TPM_ECC_CURVE        curveId,  // IN: the curve for the computations
    TPM2B_ECC_PARAMETER* dsAIn,    // IN: static private TPM key
    TPM2B_ECC_PARAMETER* deAIn,    // IN: ephemeral private TPM key
    TPMS_ECC_POINT*      QsBIn,    // IN: static public party B key
    TPMS_ECC_POINT*      QeBIn     // IN: ephemeral public party B key
)
{
    CRYPT_CURVE_INITIALIZED(E, curveId);
    CRYPT_ECC_INITIALIZED(dsA, dsAIn);
    CRYPT_ECC_INITIALIZED(deA, deAIn);
    CRYPT_POINT_INITIALIZED(QsB, QsBIn);
    CRYPT_POINT_INITIALIZED(QeB, QeBIn);
    CRYPT_INT_WORD_INITIALIZED(One, 1);
    CRYPT_POINT_VAR(QeA);
    CRYPT_ECC_NUM(XeB);
    CRYPT_POINT_VAR(Z);
    CRYPT_ECC_NUM(Ta);
    CRYPT_ECC_NUM(QeA_X);
    UINT32 w;
    TPM_RC retVal = TPM_RC_NO_RESULT;
    //
    // Parameter checks
    if(E == NULL)
        ERROR_EXIT(TPM_RC_CURVE);
    pAssert_RC(
        outZ != NULL && dsA != NULL && deA != NULL && QsB != NULL && QeB != NULL);

    // Compute the value for w
    w = ComputeWForSM2(curveId);

    // Compute the public ephemeral key pQeA = [de,A]G
    if(!ExtEcc_PointMultiply(QeA, ExtEcc_CurveGetG(curveId), deA, E))
        goto Exit;

    //  tA := (ds,A + de,A  avf(Xe,A)) mod n    (3)
    //  Compute 'tA' = ('dsA' +  'deA'  avf('XeA')) mod n
    // Ta = avf(XeA);
    // do Ta = de,A * Ta = deA * avf(XeA)
    ExtMath_Copy(QeA_X, ExtEcc_PointX(QeA));  // create mutable copy
    ExtMath_Multiply(Ta, deA, avfSm2(QeA_X, w));
    // now Ta = dsA + Ta =  dsA + deA * avf(XeA)
    ExtMath_Add(Ta, dsA, Ta);
    ExtMath_Mod(Ta, ExtEcc_CurveGetOrder(curveId));

    //  outZ = [h  tA mod n] (Qs,B + [avf(Xe,B)](Qe,B)) (4)
    // Put this in because almost every case of h is == 1 so skip the call when
    // not necessary.
    if(!ExtMath_IsEqualWord(ExtEcc_CurveGetCofactor(curveId), 1))
        // Cofactor is not 1 so compute Ta := Ta * h mod n
        ExtMath_ModMult(
            Ta, Ta, ExtEcc_CurveGetCofactor(curveId), ExtEcc_CurveGetOrder(curveId));
    // Now that 'tA' is (h * 'tA' mod n)
    // 'outZ' = ['tA'](QsB + [avf(QeB.x)](QeB)).
    ExtMath_Copy(XeB, ExtEcc_PointX(QeB));
    if(!ExtEcc_PointMultiplyAndAdd(Z, QsB, One, QeB, avfSm2(XeB, w), E))
        goto Exit;
    // QeB := [tA]QeB = [tA](QsB + [Xe,B]QeB) and check for at infinity
    if(!ExtEcc_PointMultiply(Z, Z, Ta, E))
        goto Exit;
    // Convert Crypt_Int* E to TPM2B E
    TpmEcc_PointTo2B(outZ, Z, E);
    retVal = TPM_RC_SUCCESS;
Exit:
    CRYPT_CURVE_FREE(E);
    return retVal;
}
#  endif

#endif  // CC_ZGen_2Phase