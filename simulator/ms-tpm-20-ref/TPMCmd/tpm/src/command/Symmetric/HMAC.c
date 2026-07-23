#include "Tpm.h"
#include "HMAC_fp.h"

#if CC_HMAC  // Conditional expansion of this file

/*(See part 3 specification)
// Compute HMAC on a data buffer
*/
//  Return Type: TPM_RC
//      TPM_RC_ATTRIBUTES       key referenced by 'handle' is a restricted key
//      TPM_RC_KEY              'handle' does not reference a signing key
//      TPM_RC_TYPE             key referenced by 'handle' is not an HMAC key
//      TPM_RC_VALUE           'hashAlg' is not compatible with the hash algorithm
//                              of the scheme of the object referenced by 'handle'
TPM_RC
TPM2_HMAC(HMAC_In*  in,  // IN: input parameter list
          HMAC_Out* out  // OUT: output parameter list
)
{
    HMAC_STATE    hmacState;
    OBJECT*       hmacObject;
    TPMI_ALG_HASH hashAlg;
    TPMT_PUBLIC*  publicArea;

    // Input Validation

    // Get HMAC key object and public area pointers
    hmacObject = HandleToObject(in->handle);
    pAssert_RC(hmacObject != NULL);
    publicArea = &hmacObject->publicArea;
    // Make sure that the key is an HMAC key
    if(publicArea->type != TPM_ALG_KEYEDHASH)
        return TPM_RCS_TYPE + RC_HMAC_handle;

    // and that it is unrestricted
    if(IS_ATTRIBUTE(publicArea->objectAttributes, TPMA_OBJECT, restricted))
        return TPM_RCS_ATTRIBUTES + RC_HMAC_handle;

    // and that it is a signing key
    if(!IS_ATTRIBUTE(publicArea->objectAttributes, TPMA_OBJECT, sign))
        return TPM_RCS_KEY + RC_HMAC_handle;

    // See if the key has a default
    if(publicArea->parameters.keyedHashDetail.scheme.scheme == TPM_ALG_NULL)
        // it doesn't so use the input value
        hashAlg = in->hashAlg;
    else
    {
        // key has a default so use it
        hashAlg = publicArea->parameters.keyedHashDetail.scheme.details.hmac.hashAlg;
        // and verify that the input was either the  TPM_ALG_NULL or the default
        if(in->hashAlg != TPM_ALG_NULL && in->hashAlg != hashAlg)
            hashAlg = TPM_ALG_NULL;
    }
    // if we ended up without a hash algorithm then return an error
    if(hashAlg == TPM_ALG_NULL)
        return TPM_RCS_VALUE + RC_HMAC_hashAlg;

    // Command Output

    // Start HMAC stack
    out->outHMAC.t.size = CryptHmacStart2B(
        &hmacState, hashAlg, &hmacObject->sensitive.sensitive.bits.b);
    // Adding HMAC data
    CryptDigestUpdate2B(&hmacState.hashState, &in->buffer.b);

    // Complete HMAC
    CryptHmacEnd2B(&hmacState, &out->outHMAC.b);

    return TPM_RC_SUCCESS;
}

#endif  // CC_HMAC