#include "Tpm.h"
#include "ECC_Decrypt_fp.h"
#include "CryptEccCrypt_fp.h"

#if CC_ECC_Decrypt  // Conditional expansion of this file

//  Return Type: TPM_RC
//      TPM_RC_ATTRIBUTES        key referenced by 'keyHandle' is restricted
//      TPM_RC_KEY                keyHandle does not reference an ECC key
//      TPM_RC_NO_RESULT        internal error in big number processing
//      TPM_RC_SCHEME            bad scheme
//      TPM_RC_VALUE            C3 did not match hash of recovered data
TPM_RC
TPM2_ECC_Decrypt(ECC_Decrypt_In*  in,  // IN: input parameter list
                 ECC_Decrypt_Out* out  // OUT: output parameter list
)
{
    OBJECT* key = HandleToObject(in->keyHandle);
    pAssert_RC(key != NULL);

    // Parameter validation
    // Must be the correct type of key with correct attributes
    if(key->publicArea.type != TPM_ALG_ECC)
        return TPM_RC_KEY + RC_ECC_Decrypt_keyHandle;
    if(IS_ATTRIBUTE(key->publicArea.objectAttributes, TPMA_OBJECT, restricted)
       || !IS_ATTRIBUTE(key->publicArea.objectAttributes, TPMA_OBJECT, decrypt))
        return TPM_RCS_ATTRIBUTES + RC_ECC_Decrypt_keyHandle;
    // Have to have a scheme selected
    if(!CryptEccSelectScheme(key, &in->inScheme))
        return TPM_RCS_SCHEME + RC_ECC_Decrypt_inScheme;
    //  Command Output
    return CryptEccDecrypt(
        key, &in->inScheme, &out->plainText, &in->C1.point, &in->C2, &in->C3);
}

#endif  // CC_ECC_Decrypt