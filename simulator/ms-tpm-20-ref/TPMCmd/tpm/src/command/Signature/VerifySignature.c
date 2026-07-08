#include "Tpm.h"
#include "VerifySignature_fp.h"

#if CC_VerifySignature  // Conditional expansion of this file

/*(See part 3 specification)
// This command uses loaded key to validate an asymmetric signature on a message
// with the message digest passed to the TPM.
*/
//  Return Type: TPM_RC
//      TPM_RC_ATTRIBUTES         'keyHandle' does not reference a signing key
//      TPM_RC_SIGNATURE          signature is not genuine
//      TPM_RC_SCHEME             CryptValidateSignature()
//      TPM_RC_HANDLE             the input handle is references an HMAC key but
//                                the private portion is not loaded
TPM_RC
TPM2_VerifySignature(VerifySignature_In*  in,  // IN: input parameter list
                     VerifySignature_Out* out  // OUT: output parameter list
)
{
    TPM_RC            result;
    OBJECT*           signObject = HandleToObject(in->keyHandle);
    TPMI_RH_HIERARCHY hierarchy;

    // Input Validation
    // The object to validate the signature must be a signing key.
    if(!IS_ATTRIBUTE(signObject->publicArea.objectAttributes, TPMA_OBJECT, sign))
        return TPM_RCS_ATTRIBUTES + RC_VerifySignature_keyHandle;

    // Validate Signature.  TPM_RC_SCHEME, TPM_RC_HANDLE or TPM_RC_SIGNATURE
    // error may be returned by CryptCVerifySignatrue()
    result = CryptValidateSignature(in->keyHandle, &in->digest, &in->signature);
    if(result != TPM_RC_SUCCESS)
        return RcSafeAddToResult(result, RC_VerifySignature_signature);

    // Command Output

    hierarchy = GetHierarchy(in->keyHandle);
    if(hierarchy == TPM_RH_NULL || signObject->publicArea.nameAlg == TPM_ALG_NULL)
    {
        // produce empty ticket if hierarchy is TPM_RH_NULL or nameAlg is
        // TPM_ALG_NULL
        out->validation.tag           = TPM_ST_VERIFIED;
        out->validation.hierarchy     = TPM_RH_NULL;
        out->validation.digest.t.size = 0;
    }
    else
    {
        // Compute ticket
        result = TicketComputeVerified(
            hierarchy, &in->digest, &signObject->name, &out->validation);
        if(result != TPM_RC_SUCCESS)
            return result;
    }

    return TPM_RC_SUCCESS;
}

#endif  // CC_VerifySignature