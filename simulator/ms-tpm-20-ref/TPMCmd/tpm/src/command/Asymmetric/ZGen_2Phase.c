#include "Tpm.h"
#include "ZGen_2Phase_fp.h"

#if CC_ZGen_2Phase  // Conditional expansion of this file

// This command uses the TPM to recover one or two Z values in a two phase key
// exchange protocol
//  Return Type: TPM_RC
//      TPM_RC_ATTRIBUTES               key referenced by 'keyA' is restricted or
//                                      not a decrypt key
//      TPM_RC_ECC_POINT                'inQsB' or  'inQeB' is not on the curve of
//                                      the key reference by 'keyA'
//      TPM_RC_KEY                      key referenced by 'keyA' is not an ECC key
//      TPM_RC_SCHEME                   the scheme of the key referenced by 'keyA'
//                                      is not TPM_ALG_NULL, TPM_ALG_ECDH,
//                                      TPM_ALG_ECMQV or TPM_ALG_SM2
TPM_RC
TPM2_ZGen_2Phase(ZGen_2Phase_In*  in,  // IN: input parameter list
                 ZGen_2Phase_Out* out  // OUT: output parameter list
)
{
    TPM_RC              result;
    OBJECT*             eccKey;
    TPM2B_ECC_PARAMETER r;
    TPM_ALG_ID          scheme;

    // Input Validation

    eccKey = HandleToObject(in->keyA);
    pAssert_RC(eccKey != NULL);

    // keyA must be an ECC key
    if(eccKey->publicArea.type != TPM_ALG_ECC)
        return TPM_RCS_KEY + RC_ZGen_2Phase_keyA;

    // keyA must not be restricted and must be a decrypt key
    if(IS_ATTRIBUTE(eccKey->publicArea.objectAttributes, TPMA_OBJECT, restricted)
       || !IS_ATTRIBUTE(eccKey->publicArea.objectAttributes, TPMA_OBJECT, decrypt))
        return TPM_RCS_ATTRIBUTES + RC_ZGen_2Phase_keyA;

    // if the scheme of keyA is TPM_ALG_NULL, then use the input scheme; otherwise
    // the input scheme must be the same as the scheme of keyA
    scheme = eccKey->publicArea.parameters.asymDetail.scheme.scheme;
    if(scheme != TPM_ALG_NULL)
    {
        if(scheme != in->inScheme)
            return TPM_RCS_SCHEME + RC_ZGen_2Phase_inScheme;
    }
    else
        scheme = in->inScheme;
    if(scheme == TPM_ALG_NULL)
        return TPM_RCS_SCHEME + RC_ZGen_2Phase_inScheme;

    // Input points must be on the curve of keyA
    if(!CryptEccIsPointOnCurve(eccKey->publicArea.parameters.eccDetail.curveID,
                               &in->inQsB.point))
        return TPM_RCS_ECC_POINT + RC_ZGen_2Phase_inQsB;

    if(!CryptEccIsPointOnCurve(eccKey->publicArea.parameters.eccDetail.curveID,
                               &in->inQeB.point))
        return TPM_RCS_ECC_POINT + RC_ZGen_2Phase_inQeB;

    if(!CryptGenerateR(
           &r, &in->counter, eccKey->publicArea.parameters.eccDetail.curveID, NULL))
        return TPM_RCS_VALUE + RC_ZGen_2Phase_counter;

    // Command Output

    result =
        CryptEcc2PhaseKeyExchange(&out->outZ1.point,
                                  &out->outZ2.point,
                                  eccKey->publicArea.parameters.eccDetail.curveID,
                                  scheme,
                                  &eccKey->sensitive.sensitive.ecc,
                                  &r,
                                  &in->inQsB.point,
                                  &in->inQeB.point);
    if(result == TPM_RC_SCHEME)
        return TPM_RCS_SCHEME + RC_ZGen_2Phase_inScheme;

    if(result == TPM_RC_SUCCESS)
        CryptEndCommit(in->counter);

    return result;
}
#endif  // CC_ZGen_2Phase