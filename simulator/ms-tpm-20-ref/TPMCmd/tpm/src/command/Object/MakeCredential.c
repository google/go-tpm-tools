#include "Tpm.h"
#include "MakeCredential_fp.h"

#if CC_MakeCredential  // Conditional expansion of this file

#  include "Object_spt_fp.h"

/*(See part 3 specification)
// Make Credential with an object
*/
//  Return Type: TPM_RC
//      TPM_RC_KEY              'handle' referenced an ECC key that has a unique
//                              field that is not a point on the curve of the key
//      TPM_RC_SIZE             'credential' is larger than the digest size of
//                              Name algorithm of 'handle'
//      TPM_RC_TYPE             'handle' does not reference an asymmetric
//                              decryption key
TPM_RC
TPM2_MakeCredential(MakeCredential_In*  in,  // IN: input parameter list
                    MakeCredential_Out* out  // OUT: output parameter list
)
{
    TPM_RC     result = TPM_RC_SUCCESS;

    OBJECT*    object;
    TPM2B_DATA data;

    // Input Validation

    // Get object pointer
    object = HandleToObject(in->handle);
    pAssert_RC(object != NULL);

    // input key must be an asymmetric, restricted decryption key
    // NOTE: Needs to be restricted to have a symmetric value.
    if(!CryptIsAsymAlgorithm(object->publicArea.type)
       || !IS_ATTRIBUTE(object->publicArea.objectAttributes, TPMA_OBJECT, decrypt)
       || !IS_ATTRIBUTE(object->publicArea.objectAttributes, TPMA_OBJECT, restricted))
        return TPM_RCS_TYPE + RC_MakeCredential_handle;

    // The credential information may not be larger than the digest size used for
    // the Name of the key associated with handle.
    if(in->credential.t.size > CryptHashGetDigestSize(object->publicArea.nameAlg))
        return TPM_RCS_SIZE + RC_MakeCredential_credential;

    // Command Output

    // Make encrypt key and its associated secret structure.
    out->secret.t.size = sizeof(out->secret.t.secret);
    result = CryptSecretEncrypt(object, IDENTITY_STRING, &data, &out->secret);
    if(result != TPM_RC_SUCCESS)
        return result;

    // Prepare output credential data from secret
    return SecretToCredential(
        &in->credential, &in->objectName.b, &data.b, object, &out->credentialBlob);
}

#endif  // CC_MakeCredential