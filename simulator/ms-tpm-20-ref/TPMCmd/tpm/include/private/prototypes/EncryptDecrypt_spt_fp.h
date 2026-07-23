/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar 28, 2019  Time: 08:25:18PM
 */

#ifndef _ENCRYPT_DECRYPT_SPT_FP_H_
#define _ENCRYPT_DECRYPT_SPT_FP_H_

#if CC_EncryptDecrypt2

//  Return Type: TPM_RC
//      TPM_RC_KEY          is not a symmetric decryption key with both
//                          public and private portions loaded
//      TPM_RC_SIZE         'IvIn' size is incompatible with the block cipher mode;
//                          or 'inData' size is not an even multiple of the block
//                          size for CBC or ECB mode
//      TPM_RC_VALUE        'keyHandle' is restricted and the argument 'mode' does
//                          not match the key's mode
TPM_RC
EncryptDecryptShared(TPMI_DH_OBJECT      keyHandleIn,
                     TPMI_YES_NO         decryptIn,
                     TPMI_ALG_SYM_MODE   modeIn,
                     TPM2B_IV*           ivIn,
                     TPM2B_MAX_BUFFER*   inData,
                     EncryptDecrypt_Out* out);
#endif  // CC_EncryptDecrypt

#endif  // _ENCRYPT_DECRYPT_SPT_FP_H_
