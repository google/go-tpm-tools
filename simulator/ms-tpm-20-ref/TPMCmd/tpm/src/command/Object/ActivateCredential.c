#include "Tpm.h"
#include "ActivateCredential_fp.h"

#if CC_ActivateCredential  // Conditional expansion of this file

#  include "Object_spt_fp.h"

/*(See part 3 specification)
// Activate Credential with an object
*/
//  Return Type: TPM_RC
//      TPM_RC_ATTRIBUTES       'keyHandle' does not reference a decryption key
//      TPM_RC_ECC_POINT        'secret' is invalid (when 'keyHandle' is an ECC key)
//      TPM_RC_INSUFFICIENT     'secret' is invalid (when 'keyHandle' is an ECC key)
//      TPM_RC_INTEGRITY        'credentialBlob' fails integrity test
//      TPM_RC_NO_RESULT        'secret' is invalid (when 'keyHandle' is an ECC key)
//      TPM_RC_SIZE             'secret' size is invalid or the 'credentialBlob'
//                              does not unmarshal correctly
//      TPM_RC_TYPE             'keyHandle' does not reference an asymmetric key.
//      TPM_RC_VALUE            'secret' is invalid (when 'keyHandle' is an RSA key)
TPM_RC
TPM2_ActivateCredential(ActivateCredential_In*  in,  // IN: input parameter list
                        ActivateCredential_Out* out  // OUT: output parameter list
)
{
    TPM_RC     result = TPM_RC_SUCCESS;
    OBJECT*    object;          // decrypt key
    OBJECT*    activateObject;  // key associated with credential
    TPM2B_DATA data;            // credential data

    // Input Validation

    // Get decrypt key pointer
    object = HandleToObject(in->keyHandle);
    pAssert_RC(object != NULL);

    // Get certificated object pointer
    activateObject = HandleToObject(in->activateHandle);

    // input decrypt key must be an asymmetric, restricted decryption key
    if(!CryptIsAsymAlgorithm(object->publicArea.type)
       || !IS_ATTRIBUTE(object->publicArea.objectAttributes, TPMA_OBJECT, decrypt)
       || !IS_ATTRIBUTE(object->publicArea.objectAttributes, TPMA_OBJECT, restricted))
        return TPM_RCS_TYPE + RC_ActivateCredential_keyHandle;

    // Command output

    // Decrypt input credential data via asymmetric decryption.  A
    // TPM_RC_VALUE, TPM_RC_KEY or unmarshal errors may be returned at this
    // point
    result = CryptSecretDecrypt(object, NULL, IDENTITY_STRING, &in->secret, &data);
    if(result != TPM_RC_SUCCESS)
    {
        if(result == TPM_RC_KEY)
            return TPM_RC_FAILURE;
        return RcSafeAddToResult(result, RC_ActivateCredential_secret);
    }
    // this assertion is deliberately late, after other validation has happened
    // soas to not change existing behavior of the function
    pAssert_RC(activateObject != NULL);

    // Retrieve secret data.  A TPM_RC_INTEGRITY error or unmarshal
    // errors may be returned at this point
    result = CredentialToSecret(&in->credentialBlob.b,
                                &activateObject->name.b,
                                &data.b,
                                object,
                                &out->certInfo);
    if(result != TPM_RC_SUCCESS)
        return RcSafeAddToResult(result, RC_ActivateCredential_credentialBlob);

    return TPM_RC_SUCCESS;
}

#endif  // CC_ActivateCredential