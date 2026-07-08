#include "Tpm.h"
#include "HMAC_Start_fp.h"

#if CC_HMAC_Start  // Conditional expansion of this file

/*(See part 3 specification)
// Initialize a HMAC sequence and create a sequence object
*/
//  Return Type: TPM_RC
//      TPM_RC_ATTRIBUTES       key referenced by 'handle' is not a signing key
//                              or is restricted
//      TPM_RC_OBJECT_MEMORY    no space to create an internal object
//      TPM_RC_KEY              key referenced by 'handle' is not an HMAC key
//      TPM_RC_VALUE            'hashAlg' is not compatible with the hash algorithm
//                              of the scheme of the object referenced by 'handle'
TPM_RC
TPM2_HMAC_Start(HMAC_Start_In*  in,  // IN: input parameter list
                HMAC_Start_Out* out  // OUT: output parameter list
)
{
    OBJECT*      keyObject;
    TPMT_PUBLIC* publicArea;
    TPM_ALG_ID   hashAlg;

    // Input Validation

    // Get HMAC key object and public area pointers
    keyObject = HandleToObject(in->handle);
    pAssert_RC(keyObject != NULL);

    publicArea = &keyObject->publicArea;
    pAssert_RC(publicArea != NULL);

    // Make sure that the key is an HMAC key
    if(publicArea->type != TPM_ALG_KEYEDHASH)
        return TPM_RCS_TYPE + RC_HMAC_Start_handle;

    // and that it is unrestricted
    if(IS_ATTRIBUTE(publicArea->objectAttributes, TPMA_OBJECT, restricted))
        return TPM_RCS_ATTRIBUTES + RC_HMAC_Start_handle;

    // and that it is a signing key
    if(!IS_ATTRIBUTE(publicArea->objectAttributes, TPMA_OBJECT, sign))
        return TPM_RCS_KEY + RC_HMAC_Start_handle;

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
        return TPM_RCS_VALUE + RC_HMAC_Start_hashAlg;

    // Internal Data Update

    // Create a HMAC sequence object. A TPM_RC_OBJECT_MEMORY error may be
    // returned at this point
    return ObjectCreateHMACSequence(
        hashAlg, keyObject, &in->auth, &out->sequenceHandle);
}

#endif  // CC_HMAC_Start