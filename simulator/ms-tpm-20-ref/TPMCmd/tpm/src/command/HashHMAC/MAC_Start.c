#include "Tpm.h"
#include "MAC_Start_fp.h"

#if CC_MAC_Start  // Conditional expansion of this file

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
TPM2_MAC_Start(MAC_Start_In*  in,  // IN: input parameter list
               MAC_Start_Out* out  // OUT: output parameter list
)
{
    OBJECT*      keyObject;
    TPMT_PUBLIC* publicArea;
    TPM_RC       result;

    // Input Validation

    // Get HMAC key object and public area pointers
    keyObject = HandleToObject(in->handle);
    pAssert_RC(keyObject != NULL);
    publicArea = &keyObject->publicArea;
    pAssert_RC(publicArea != NULL);

    // Make sure that the key can do what is required
    result = CryptSelectMac(publicArea, &in->inScheme);
    // If the key is not able to do a MAC, indicate that the handle selects an
    // object that can't do a MAC
    if(result == TPM_RCS_TYPE)
        return TPM_RCS_TYPE + RC_MAC_Start_handle;
    // If there is another error type, indicate that the scheme and key are not
    // compatible
    if(result != TPM_RC_SUCCESS)
        return RcSafeAddToResult(result, RC_MAC_Start_inScheme);
    // Make sure that the key is not restricted
    if(IS_ATTRIBUTE(publicArea->objectAttributes, TPMA_OBJECT, restricted))
        return TPM_RCS_ATTRIBUTES + RC_MAC_Start_handle;
    // and that it is a signing key
    if(!IS_ATTRIBUTE(publicArea->objectAttributes, TPMA_OBJECT, sign))
        return TPM_RCS_KEY + RC_MAC_Start_handle;

    // Internal Data Update
    // Create a HMAC sequence object. A TPM_RC_OBJECT_MEMORY error may be
    // returned at this point
    return ObjectCreateHMACSequence(
        in->inScheme, keyObject, &in->auth, &out->sequenceHandle);
}

#endif  // CC_MAC_Start