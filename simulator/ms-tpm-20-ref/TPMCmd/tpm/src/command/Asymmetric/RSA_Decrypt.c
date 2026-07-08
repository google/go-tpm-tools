#include "Tpm.h"
#include "RSA_Decrypt_fp.h"

#if CC_RSA_Decrypt  // Conditional expansion of this file

/*(See part 3 specification)
// decrypts the provided data block and removes the padding if applicable
*/
//  Return Type: TPM_RC
//      TPM_RC_ATTRIBUTES       'decrypt' is not SET or if 'restricted' is SET in
//                              the key referenced by 'keyHandle'
//      TPM_RC_BINDING          The public and private parts of the key are not
//                              properly bound
//      TPM_RC_KEY              'keyHandle' does not reference an unrestricted
//                              decrypt key
//      TPM_RC_SCHEME           incorrect input scheme, or the chosen
//                              'scheme' is not a valid RSA decrypt scheme
//      TPM_RC_SIZE             'cipherText' is not the size of the modulus
//                              of key referenced by 'keyHandle'
//      TPM_RC_VALUE            'label' is not a null terminated string or the value
//                              of 'cipherText' is greater that the modulus of
//                              'keyHandle' or the encoding of the data is not
//                              valid

TPM_RC
TPM2_RSA_Decrypt(RSA_Decrypt_In*  in,  // IN: input parameter list
                 RSA_Decrypt_Out* out  // OUT: output parameter list
)
{
    TPM_RC            result;
    OBJECT*           rsaKey;
    TPMT_RSA_DECRYPT* scheme;

    // Input Validation

    rsaKey = HandleToObject(in->keyHandle);
    pAssert_RC(rsaKey != NULL);

    // The selected key must be an RSA key
    if(rsaKey->publicArea.type != TPM_ALG_RSA)
        return TPM_RCS_KEY + RC_RSA_Decrypt_keyHandle;

    // The selected key must be an unrestricted decryption key
    if(IS_ATTRIBUTE(rsaKey->publicArea.objectAttributes, TPMA_OBJECT, restricted)
       || !IS_ATTRIBUTE(rsaKey->publicArea.objectAttributes, TPMA_OBJECT, decrypt))
        return TPM_RCS_ATTRIBUTES + RC_RSA_Decrypt_keyHandle;

    // NOTE: Proper operation of this command requires that the sensitive area
    // of the key is loaded. This is assured because authorization is required
    // to use the sensitive area of the key. In order to check the authorization,
    // the sensitive area has to be loaded, even if authorization is with policy.

    // If label is present, make sure that it is a NULL-terminated string
    if(!IsLabelProperlyFormatted(&in->label.b))
        return TPM_RCS_VALUE + RC_RSA_Decrypt_label;
    // Command Output
    // Select a scheme for decrypt.
    scheme = CryptRsaSelectScheme(in->keyHandle, &in->inScheme);
    if(scheme == NULL)
        return TPM_RCS_SCHEME + RC_RSA_Decrypt_inScheme;

    // Decryption.  TPM_RC_VALUE, TPM_RC_SIZE, and TPM_RC_KEY error may be
    // returned by CryptRsaDecrypt.
    // NOTE: CryptRsaDecrypt can also return TPM_RC_ATTRIBUTES or TPM_RC_BINDING
    // when the key is not a decryption key but that was checked above.
    out->message.t.size = sizeof(out->message.t.buffer);
    result              = CryptRsaDecrypt(
        &out->message.b, &in->cipherText.b, rsaKey, scheme, &in->label.b);
    return result;
}

#endif  // CC_RSA_Decrypt