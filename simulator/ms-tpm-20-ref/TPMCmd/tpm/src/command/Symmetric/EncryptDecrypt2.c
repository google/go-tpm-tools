#include "Tpm.h"
#include "EncryptDecrypt2_fp.h"
#include "EncryptDecrypt_fp.h"
#include "EncryptDecrypt_spt_fp.h"

#if CC_EncryptDecrypt2  // Conditional expansion of this file

/*(See part 3 specification)
// symmetric encryption or decryption using modified parameter list
*/
//  Return Type: TPM_RC
//      TPM_RC_KEY          is not a symmetric decryption key with both
//                          public and private portions loaded
//      TPM_RC_SIZE         'IvIn' size is incompatible with the block cipher mode;
//                          or 'inData' size is not an even multiple of the block
//                          size for CBC or ECB mode
//      TPM_RC_VALUE        'keyHandle' is restricted and the argument 'mode' does
//                          not match the key's mode
TPM_RC
TPM2_EncryptDecrypt2(EncryptDecrypt2_In*  in,  // IN: input parameter list
                     EncryptDecrypt2_Out* out  // OUT: output parameter list
)
{
    TPM_RC result;
    // EncryptDecyrptShared() performs the operations as shown in
    // TPM2_EncrypDecrypt
    result = EncryptDecryptShared(in->keyHandle,
                                  in->decrypt,
                                  in->mode,
                                  &in->ivIn,
                                  &in->inData,
                                  (EncryptDecrypt_Out*)out);
    // Handle response code swizzle.
    switch(result)
    {
        case TPM_RCS_MODE + RC_EncryptDecrypt_mode:
            result = TPM_RCS_MODE + RC_EncryptDecrypt2_mode;
            break;
        case TPM_RCS_SIZE + RC_EncryptDecrypt_ivIn:
            result = TPM_RCS_SIZE + RC_EncryptDecrypt2_ivIn;
            break;
        case TPM_RCS_SIZE + RC_EncryptDecrypt_inData:
            result = TPM_RCS_SIZE + RC_EncryptDecrypt2_inData;
            break;
        default:
            break;
    }
    return result;
}

#endif  // CC_EncryptDecrypt2