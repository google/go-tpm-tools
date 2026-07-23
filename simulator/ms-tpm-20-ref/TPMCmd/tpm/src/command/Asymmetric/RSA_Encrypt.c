#include "Tpm.h"
#include "RSA_Encrypt_fp.h"

#if CC_RSA_Encrypt  // Conditional expansion of this file

/*(See part 3 specification)
// This command performs the padding and encryption of a data block
*/
//  Return Type: TPM_RC
//      TPM_RC_ATTRIBUTES           'decrypt' attribute is not SET in key referenced
//                                  by 'keyHandle'
//      TPM_RC_KEY                  'keyHandle' does not reference an RSA key
//      TPM_RC_SCHEME               incorrect input scheme, or the chosen
//                                  scheme is not a valid RSA decrypt scheme
//      TPM_RC_VALUE                the numeric value of 'message' is greater than
//                                  the public modulus of the key referenced by
//                                  'keyHandle', or 'label' is not a null-terminated
//                                  string
TPM_RC
TPM2_RSA_Encrypt(RSA_Encrypt_In*  in,  // IN: input parameter list
                 RSA_Encrypt_Out* out  // OUT: output parameter list
)
{
    TPM_RC            result;
    OBJECT*           rsaKey;
    TPMT_RSA_DECRYPT* scheme;
    // Input Validation
    rsaKey = HandleToObject(in->keyHandle);
    pAssert_RC(rsaKey != NULL);

    // selected key must be an RSA key
    if(rsaKey->publicArea.type != TPM_ALG_RSA)
        return TPM_RCS_KEY + RC_RSA_Encrypt_keyHandle;
    // selected key must have the decryption attribute
    if(!IS_ATTRIBUTE(rsaKey->publicArea.objectAttributes, TPMA_OBJECT, decrypt))
        return TPM_RCS_ATTRIBUTES + RC_RSA_Encrypt_keyHandle;

    // Is there a label?
    if(!IsLabelProperlyFormatted(&in->label.b))
        return TPM_RCS_VALUE + RC_RSA_Encrypt_label;
    // Command Output
    // Select a scheme for encryption
    scheme = CryptRsaSelectScheme(in->keyHandle, &in->inScheme);
    if(scheme == NULL)
        return TPM_RCS_SCHEME + RC_RSA_Encrypt_inScheme;

    // Encryption.  TPM_RC_VALUE, or TPM_RC_SCHEME errors my be returned buy
    // CryptEncyptRSA.
    out->outData.t.size = sizeof(out->outData.t.buffer);

    result              = CryptRsaEncrypt(
        &out->outData, &in->message.b, rsaKey, scheme, &in->label.b, NULL);
    return result;
}

#endif  // CC_RSA_Encrypt