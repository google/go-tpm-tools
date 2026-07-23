#include "Tpm.h"
#include "ECDH_ZGen_fp.h"

#if CC_ECDH_ZGen  // Conditional expansion of this file

/*(See part 3 specification)
// This command uses the TPM to recover the Z value from a public point
*/
//  Return Type: TPM_RC
//      TPM_RC_ATTRIBUTES               key referenced by 'keyA' is restricted or
//                                      not a decrypt key
//      TPM_RC_KEY                      key referenced by 'keyA' is not an ECC key
//      TPM_RC_NO_RESULT                multiplying 'inPoint' resulted in a
//                                      point at infinity
//      TPM_RC_SCHEME                   the scheme of the key referenced by 'keyA'
//                                      is not TPM_ALG_NULL, TPM_ALG_ECDH,
TPM_RC
TPM2_ECDH_ZGen(ECDH_ZGen_In*  in,  // IN: input parameter list
               ECDH_ZGen_Out* out  // OUT: output parameter list
)
{
    TPM_RC  result;
    OBJECT* eccKey;

    // Input Validation
    eccKey = HandleToObject(in->keyHandle);
    pAssert_RC(eccKey != NULL);

    // Selected key must be a non-restricted, decrypt ECC key
    if(eccKey->publicArea.type != TPM_ALG_ECC)
        return TPM_RCS_KEY + RC_ECDH_ZGen_keyHandle;
    // Selected key needs to be unrestricted with the 'decrypt' attribute
    if(IS_ATTRIBUTE(eccKey->publicArea.objectAttributes, TPMA_OBJECT, restricted)
       || !IS_ATTRIBUTE(eccKey->publicArea.objectAttributes, TPMA_OBJECT, decrypt))
        return TPM_RCS_ATTRIBUTES + RC_ECDH_ZGen_keyHandle;
    // Make sure the scheme allows this use
    if(eccKey->publicArea.parameters.eccDetail.scheme.scheme != TPM_ALG_ECDH
       && eccKey->publicArea.parameters.eccDetail.scheme.scheme != TPM_ALG_NULL)
        return TPM_RCS_SCHEME + RC_ECDH_ZGen_keyHandle;
    // Command Output
    // Compute Z. TPM_RC_ECC_POINT or TPM_RC_NO_RESULT may be returned here.
    result = CryptEccPointMultiply(&out->outPoint.point,
                                   eccKey->publicArea.parameters.eccDetail.curveID,
                                   &in->inPoint.point,
                                   &eccKey->sensitive.sensitive.ecc,
                                   NULL,
                                   NULL);
    if(result != TPM_RC_SUCCESS)
        return RcSafeAddToResult(result, RC_ECDH_ZGen_inPoint);
    return result;
}

#endif  // CC_ECDH_ZGen